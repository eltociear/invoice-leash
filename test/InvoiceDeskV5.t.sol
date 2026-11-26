// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {InvoiceDeskV5} from "../contracts/InvoiceDeskV5.sol";
import {PqcVerifyStandIn, PqcKeyStatusStandIn} from "./InvoiceDesk.t.sol";
import {MockToken, FalseToken} from "./InvoiceDeskV2.t.sol";

/// A token that keeps 1% of every transfer (a "fee on transfer"): the vendor receives less than invoiced.
contract FeeTokenV5 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        allowance[f][msg.sender] -= a; balanceOf[f] -= a; balanceOf[to] += a - a / 100; return true;
    }
}

/// A token that moves the funds but reports failure. ERC-20 says false means failed: the desk must not
/// book it as paid, even though the vendor's balance rose.
contract MovesButReturnsFalseV5 {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) { balanceOf[f] -= a; balanceOf[to] += a; return false; }
}

contract InvoiceDeskV5Test is Test {
    address constant VERIFY = 0x0000000000000000000000000000000000000a01;
    address constant STATUS = 0x0000000000000000000000000000000000000a02;
    uint256 constant N = 16;
    string fx;
    InvoiceDeskV5 desk;
    MockToken fusd;
    address payer; address payer2; address hostline; address tokenwell; address mallory; address otherToken;

    event InvoicePaid(address indexed payer, address indexed vendor, bytes32 indexed id, address token, uint256 amount, address by);

    struct Case { bytes pubkey; bytes signature; bytes message; bool valid; address payer; address vendor; address token; uint256 amount; bytes32 id; uint64 dueBy; }

    function setUp() public {
        fx = vm.readFile("test/fixtures/mldsa-v5.json");
        vm.chainId(vm.parseJsonUint(fx, ".chainId"));
        payer = vm.parseJsonAddress(fx, ".addresses.payer");
        payer2 = vm.parseJsonAddress(fx, ".addresses.payer2");
        hostline = vm.parseJsonAddress(fx, ".addresses.hostline");
        tokenwell = vm.parseJsonAddress(fx, ".addresses.tokenwell");
        mallory = vm.parseJsonAddress(fx, ".addresses.mallory");
        otherToken = vm.parseJsonAddress(fx, ".tokens.other");

        vm.etch(VERIFY, address(new PqcVerifyStandIn()).code);
        vm.etch(STATUS, address(new PqcKeyStatusStandIn()).code);
        for (uint256 i = 0; i < N; i++) { Case memory c = _case(i); PqcVerifyStandIn(VERIFY).record(c.pubkey, c.signature, c.message, c.valid); }
        // the agent's own ML-DSA-87 signatures (real, from test/fixtures.mjs), and its signer's key on chain
        bytes memory signerKey = vm.parseJsonBytes(fx, ".keys.agentsigner");
        for (uint256 i = 0; i < N; i++) {
            string memory k = string.concat(".agentSigs.0x000000000000000000000000000000000000A9E7[", vm.toString(i), "]");
            bytes memory m = vm.parseJsonBytes(fx, string.concat(k, ".message"));
            bytes memory sg = vm.parseJsonBytes(fx, string.concat(k, ".signature"));
            PqcVerifyStandIn(VERIFY).record(signerKey, sg, m, true);
            agentIdx[keccak256(abi.encode(_case(i).message, _case(i).signature))] = i + 1; // the signature itself is read from the fixture when needed
        }
        PqcVerifyStandIn(VERIFY).record(signerKey, vm.parseJsonBytes(fx, ".foreign.signature"), vm.parseJsonBytes(fx, ".foreign.message"), false);
        PqcKeyStatusStandIn(STATUS).set(SIGNER, true, 1, signerKey, true);
        for (uint256 i = 0; i < 4; i++) { Case memory x = _extra(i); PqcVerifyStandIn(VERIFY).record(x.pubkey, x.signature, x.message, x.valid); }
        for (uint256 i = 0; i < 4; i++) PqcVerifyStandIn(VERIFY).record(signerKey, _xsig(i), vm.parseJsonBytes(fx, string.concat(".extraAgentSigs[", vm.toString(i), "].message")), true);
        // the new bindings, each with its real ML-DSA-87 answer (test/fixtures.mjs, `bindings`)
        for (uint256 i = 0; i < 4; i++) PqcVerifyStandIn(VERIFY).record(signerKey, vm.parseJsonBytes(fx, _b(i, "agentSignature")), vm.parseJsonBytes(fx, _b(i, "message")), vm.parseJsonBool(fx, _b(i, "valid")));
        VU = uint64(vm.parseJsonUint(fx, ".validUntil"));
        PqcKeyStatusStandIn(STATUS).set(hostline, true, 1, vm.parseJsonBytes(fx, ".keys.hostline"), true);
        PqcKeyStatusStandIn(STATUS).set(tokenwell, true, 1, vm.parseJsonBytes(fx, ".keys.tokenwell"), true);
        PqcKeyStatusStandIn(STATUS).set(mallory, true, 1, vm.parseJsonBytes(fx, ".keys.mallory"), true);

        deployCodeTo("MockToken", vm.parseJsonAddress(fx, ".tokens.fusd"));
        fusd = MockToken(vm.parseJsonAddress(fx, ".tokens.fusd"));
        deployCodeTo("MockToken", otherToken);
        deployCodeTo("InvoiceDeskV5.sol:InvoiceDeskV5", vm.parseJsonAddress(fx, ".addresses.desk"));
        desk = InvoiceDeskV5(vm.parseJsonAddress(fx, ".addresses.desk"));

        fusd.mint(payer, 1000e6);
        MockToken(otherToken).mint(payer, 1000e6);
        vm.deal(payer, 10 ether);
        vm.startPrank(payer);
        desk.approveVendor(hostline);
        desk.approveVendor(tokenwell);
        fusd.approve(address(desk), 600e6);
        MockToken(otherToken).approve(address(desk), 600e6);
        vm.stopPrank();
        vm.warp(1795000000);
    }

    function _k(uint256 i, string memory f) internal pure returns (string memory) { return string.concat(".cases[", vm.toString(i), "].", f); }
    function _case(uint256 i) internal view returns (Case memory c) {
        c.pubkey = vm.parseJsonBytes(fx, _k(i, "pubkey")); c.signature = vm.parseJsonBytes(fx, _k(i, "signature"));
        c.message = vm.parseJsonBytes(fx, _k(i, "message")); c.valid = vm.parseJsonBool(fx, _k(i, "valid"));
        c.payer = vm.parseJsonAddress(fx, _k(i, "payer")); c.vendor = vm.parseJsonAddress(fx, _k(i, "vendor"));
        c.token = vm.parseJsonAddress(fx, _k(i, "token")); c.amount = vm.parseJsonUint(fx, _k(i, "amount"));
        c.id = vm.parseJsonBytes32(fx, _k(i, "id")); c.dueBy = uint64(vm.parseJsonUint(fx, _k(i, "dueBy")));
    }
    /// Genuine invoices that differ from genuine_fusd in one field (test/fixtures.mjs, `extras`).
    function _extra(uint256 i) internal view returns (Case memory c) {
        string memory k = string.concat(".extras[", vm.toString(i), "].");
        c.pubkey = vm.parseJsonBytes(fx, string.concat(k, "pubkey")); c.signature = vm.parseJsonBytes(fx, string.concat(k, "signature"));
        c.message = vm.parseJsonBytes(fx, string.concat(k, "message")); c.valid = vm.parseJsonBool(fx, string.concat(k, "valid"));
        c.payer = vm.parseJsonAddress(fx, string.concat(k, "payer")); c.vendor = vm.parseJsonAddress(fx, string.concat(k, "vendor"));
        c.token = vm.parseJsonAddress(fx, string.concat(k, "token")); c.amount = vm.parseJsonUint(fx, string.concat(k, "amount"));
        c.id = vm.parseJsonBytes32(fx, string.concat(k, "id")); c.dueBy = uint64(vm.parseJsonUint(fx, string.concat(k, "dueBy")));
    }
    function _named(string memory name) internal view returns (Case memory) {
        for (uint256 i = 0; i < N; i++) if (keccak256(bytes(vm.parseJsonString(fx, _k(i, "name")))) == keccak256(bytes(name))) return _case(i);
        revert(string.concat("no fixture ", name));
    }
    /// The new bindings, as presented to the desk (test/fixtures.mjs, `bindings`).
    function _b(uint256 i, string memory f) internal pure returns (string memory) { return string.concat(".bindings[", vm.toString(i), "].", f); }
    address constant SIGNER = address(0x5161);
    /// The deadline every fixture agent signature carries (fixed, a week after the fixtures' due date).
    uint64 VU;
    /// (invoice bytes, vendor signature) => case index + 1: V5's agent signature binds both, so forged and
    /// genuine copies of the same fields have different agent signatures.
    mapping(bytes32 => uint256) agentIdx;
    /// The agent signer's ML-DSA-87 signature over this case's payment (ignored when the payer pays).
    function _asig(Case memory c) internal view returns (bytes memory) {
        uint256 i = agentIdx[keccak256(abi.encode(c.message, c.signature))];
        if (i == 0) return "";
        return vm.parseJsonBytes(fx, string.concat(".agentSigs.0x000000000000000000000000000000000000A9E7[", vm.toString(i - 1), "].signature"));
    }

    function _pay(Case memory c, uint256 value) internal {
        vm.prank(c.payer);
        desk.pay{value: value}(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, _asig(c), VU);
    }

    function test_standIn_answers_as_real_mldsa87() public view {
        for (uint256 i = 0; i < N; i++) {
            Case memory c = _case(i);
            (bool ok, bytes memory ret) = VERIFY.staticcall(abi.encodeWithSignature("pqcVerify(bytes,bytes,bytes)", c.pubkey, c.signature, c.message));
            assertTrue(ok);
            assertEq(abi.decode(ret, (bool)), c.valid, vm.parseJsonString(fx, _k(i, "name")));
        }
    }

    function test_invoiceMessage_matches_offchain_encoding() public view {
        Case memory c = _named("genuine_fusd");
        assertEq(desk.invoiceMessage(c.payer, c.vendor, c.token, c.amount, c.id, c.dueBy), c.message);
        assertEq(c.message.length, 288);
    }

    function test_pays_fusd_invoice_from_the_payers_balance() public {
        Case memory c = _named("genuine_fusd");
        vm.expectEmit(true, true, true, true, address(desk));
        emit InvoicePaid(c.payer, c.vendor, c.id, c.token, c.amount, c.payer);
        _pay(c, 0);
        assertEq(fusd.balanceOf(hostline), 80e6);
        assertEq(fusd.balanceOf(payer), 920e6);
        assertEq(fusd.allowance(payer, address(desk)), 520e6, "allowance consumed: the owner's AP budget");
        assertEq(fusd.balanceOf(address(desk)), 0, "the desk never holds tokens");
    }

    function test_pays_native_qor_invoice() public {
        Case memory c = _named("genuine_native_qor");
        _pay(c, c.amount);
        assertEq(hostline.balance, c.amount);
    }

    function test_refuses_qor_sent_with_an_fusd_invoice() public {
        Case memory c = _named("genuine_fusd");
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.WrongAmount.selector, 1, 0));
        _pay(c, 1);
    }

    function test_refuses_a_native_qor_invoice_paid_short() public {
        Case memory c = _named("genuine_native_qor");
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.WrongAmount.selector, c.amount - 1, c.amount));
        _pay(c, c.amount - 1);
        assertFalse(desk.paid(payer, hostline, c.id));
    }

    function test_the_currency_is_signed() public {
        vm.expectRevert(InvoiceDeskV5.BadSignature.selector);
        _pay(_named("paid_in_qor_instead"), 80e6);
        vm.expectRevert(InvoiceDeskV5.BadSignature.selector);
        _pay(_named("paid_in_other_token"), 0);
    }

    function test_refuses_every_tampering() public {
        string[6] memory names = ["forged_by_mallory_as_hostline", "amount_edited", "payee_swapped_to_tokenwell", "due_extended", "one_bit_flipped", "paid_in_other_token"];
        for (uint256 i = 0; i < names.length; i++) {
            Case memory c = _named(names[i]);
            vm.prank(payer);
            vm.expectRevert(InvoiceDeskV5.BadSignature.selector);
            desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, _asig(c), VU);
        }
        assertEq(fusd.balanceOf(payer), 1000e6);
    }

    function test_refuses_on_another_desk() public {
        address other = vm.parseJsonAddress(fx, ".addresses.desk2");
        deployCodeTo("InvoiceDeskV5.sol:InvoiceDeskV5", other);
        vm.startPrank(payer);
        InvoiceDeskV5(other).approveVendor(hostline);
        fusd.approve(other, 600e6);
        Case memory c = _named("genuine_fusd"); // signed for the first desk
        vm.expectRevert(InvoiceDeskV5.BadSignature.selector);
        InvoiceDeskV5(other).pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, _asig(c), VU);
        vm.stopPrank();
    }

    function test_refuses_other_payer() public {
        vm.prank(payer2);
        desk.approveVendor(hostline);
        Case memory c = _named("other_payer"); // fields name payer2, signature is for payer
        vm.expectRevert(InvoiceDeskV5.BadSignature.selector);
        _pay(c, 0);
    }

    function test_refuses_unknown_vendor_even_with_valid_signature() public {
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.UnknownVendor.selector, mallory));
        _pay(_named("mallory_own_invoice"), 0);
    }

    function test_refuses_replay_and_edited_copy_is_still_a_forgery() public {
        Case memory c = _named("genuine_fusd");
        _pay(c, 0);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.AlreadyPaid.selector, c.id));
        _pay(c, 0);
        vm.expectRevert(InvoiceDeskV5.BadSignature.selector);
        _pay(_named("amount_edited"), 0);
    }

    function test_past_due_agent_refused_payer_in_person_may_settle() public {
        _asAgent();
        Case memory c = _named("genuine_fusd");
        vm.warp(uint256(c.dueBy) + 1);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.PastDue.selector, c.dueBy));
        _agentPays(c);
        _pay(c, 0); // the company, in person: a late invoice is still a debt
        assertEq(fusd.balanceOf(hostline), 80e6);
        assertTrue(desk.paid(payer, hostline, c.id));
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.AlreadyPaid.selector, c.id));
        _pay(c, 0);
    }

    function test_late_payment_still_needs_a_genuine_signature() public {
        Case memory c = _named("due_extended"); // someone moved the due date: the signature no longer matches
        vm.warp(uint256(c.dueBy) + 1);
        vm.expectRevert(InvoiceDeskV5.BadSignature.selector);
        _pay(c, 0);
    }

    // ------------------------------------------------------------------ what V3 changes

    function test_invoice_numbers_are_per_vendor() public {
        Case memory h = _named("genuine_fusd");
        Case memory t = _named("tokenwell_same_id_as_hostline");
        assertEq(h.id, t.id, "both vendors used the same invoice number");
        _pay(h, 0);
        _pay(t, 0); // V2 refused this one as AlreadyPaid
        assertEq(fusd.balanceOf(hostline), 80e6);
        assertEq(fusd.balanceOf(tokenwell), 50e6);
        assertTrue(desk.paid(payer, hostline, h.id) && desk.paid(payer, tokenwell, t.id));
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.AlreadyPaid.selector, t.id));
        _pay(t, 0); // each still only once
    }

    function test_zero_amount_is_refused() public {
        vm.expectRevert(InvoiceDeskV5.ZeroAmount.selector);
        _pay(_named("zero_amount"), 0);
        _asAgent();
        vm.expectRevert(InvoiceDeskV5.ZeroAmount.selector);
        _agentPays(_named("zero_amount"));
    }

    function test_a_token_that_moves_funds_but_returns_false_is_refused() public {
        Case memory c = _named("fee_taking_token"); // any genuinely signed invoice whose token we control
        deployCodeTo("InvoiceDeskV5.t.sol:MovesButReturnsFalseV5", c.token);
        MovesButReturnsFalseV5(c.token).mint(payer, 1000e6);
        vm.expectRevert(InvoiceDeskV5.TransferFailed.selector);
        _pay(c, 0);
        assertFalse(desk.paid(payer, hostline, c.id), "rolled back");
    }

    function test_a_token_that_takes_a_fee_is_refused() public {
        Case memory c = _named("fee_taking_token");
        deployCodeTo("InvoiceDeskV5.t.sol:FeeTokenV5", c.token);
        FeeTokenV5(c.token).mint(payer, 1000e6);
        vm.prank(payer);
        FeeTokenV5(c.token).approve(address(desk), 600e6);
        vm.expectRevert(InvoiceDeskV5.TransferFailed.selector); // the vendor would get 79.2, not 80
        _pay(c, 0);
        assertFalse(desk.paid(payer, hostline, c.id), "rolled back");
        assertEq(FeeTokenV5(c.token).balanceOf(hostline), 0);
    }

    function test_allowance_is_a_cap() public {
        vm.prank(payer);
        fusd.approve(address(desk), 79e6);
        vm.expectRevert(InvoiceDeskV5.TransferFailed.selector);
        _pay(_named("genuine_fusd"), 0);
        assertFalse(desk.paid(payer, hostline, _named("genuine_fusd").id), "rolled back");
    }

    function test_insufficient_balance_rolls_back() public {
        vm.prank(payer);
        fusd.transfer(address(1), 950e6);
        vm.expectRevert(InvoiceDeskV5.TransferFailed.selector);
        _pay(_named("genuine_fusd"), 0);
    }

    function test_token_without_code_is_refused() public {
        Case memory c = _named("genuine_fusd");
        vm.etch(c.token, "");
        vm.expectRevert(InvoiceDeskV5.TransferFailed.selector);
        _pay(c, 0);
    }

    function test_token_returning_false_is_refused() public {
        Case memory c = _named("genuine_fusd");
        vm.etch(c.token, type(FalseToken).runtimeCode);
        vm.expectRevert(InvoiceDeskV5.TransferFailed.selector);
        _pay(c, 0);
    }

    function test_vendor_key_must_be_proven_ml_dsa_87() public {
        PqcKeyStatusStandIn(STATUS).set(hostline, true, 1, vm.parseJsonBytes(fx, ".keys.hostline"), false);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.VendorKeyNotProven.selector, hostline));
        _pay(_named("genuine_fusd"), 0);
    }

    function test_vendor_key_of_another_algorithm_or_unregistered_is_refused() public {
        bytes memory pk = vm.parseJsonBytes(fx, ".keys.hostline");
        PqcKeyStatusStandIn(STATUS).set(hostline, true, 2, pk, true); // registered and proven, but not ML-DSA-87
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.VendorKeyNotProven.selector, hostline));
        _pay(_named("genuine_fusd"), 0);
        PqcKeyStatusStandIn(STATUS).set(hostline, false, 1, pk, true); // not registered
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.VendorKeyNotProven.selector, hostline));
        _pay(_named("genuine_fusd"), 0);
    }

    function test_vendor_key_rotated_old_invoices_no_longer_verify() public {
        // Hostline's registered key is replaced (here by Tokenwell's): invoices signed with the old key now fail.
        PqcKeyStatusStandIn(STATUS).set(hostline, true, 1, vm.parseJsonBytes(fx, ".keys.tokenwell"), true);
        vm.expectRevert(InvoiceDeskV5.BadSignature.selector);
        _pay(_named("genuine_fusd"), 0);
    }

    function testFuzz_any_other_amount_is_refused(uint256 amount) public {
        Case memory c = _named("genuine_fusd");
        vm.assume(amount != c.amount && amount <= 600e6);
        vm.prank(payer);
        vm.expectRevert(InvoiceDeskV5.BadSignature.selector);
        desk.pay(c.payer, c.token, payable(c.vendor), amount, c.id, c.dueBy, c.signature, _asig(c), VU);
    }

    function testFuzz_any_other_token_is_refused(address token) public {
        Case memory c = _named("genuine_fusd");
        vm.assume(token != c.token);
        vm.prank(payer);
        vm.expectRevert(InvoiceDeskV5.BadSignature.selector);
        desk.pay(c.payer, token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, _asig(c), VU);
    }

    // ------------------------------------------------------------------ the agent: its own account, the payer's money

    address agent = address(0xA9E7);

    function _asAgent() internal {
        vm.startPrank(payer);
        desk.setAgent(agent, true); desk.setAgentSigner(agent, SIGNER);
        desk.setLimit(address(fusd), 100e6, 250e6);
        vm.stopPrank();
    }
    function _agentPays(Case memory c) internal {
        vm.prank(agent);
        desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, _asig(c), VU);
    }

    function test_agent_pays_from_the_payers_balance_and_holds_nothing() public {
        _asAgent();
        Case memory c = _named("genuine_fusd");
        vm.expectEmit(true, true, true, true, address(desk));
        emit InvoicePaid(c.payer, c.vendor, c.id, c.token, c.amount, agent);
        _agentPays(c);
        assertEq(fusd.balanceOf(hostline), 80e6);
        assertEq(fusd.balanceOf(payer), 920e6);
        assertEq(fusd.balanceOf(agent), 0);
        assertEq(desk.remainingToday(payer, address(fusd)), 170e6);
    }

    function test_unnamed_account_cannot_pay_for_the_payer() public {
        Case memory c = _named("genuine_fusd");
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.NotPayersAgent.selector, agent));
        _agentPays(c);
    }

    function test_removing_the_agent_is_a_kill_switch() public {
        _asAgent();
        vm.prank(payer);
        desk.setAgent(agent, false);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.NotPayersAgent.selector, agent));
        _agentPays(_named("genuine_fusd"));
    }

    function test_agent_limits_are_the_payers_alone() public {
        _asAgent();
        // the agent configures ITS OWN payer entry: no effect on the payer's limits or agents
        vm.startPrank(agent);
        desk.setLimit(address(fusd), type(uint256).max, type(uint256).max);
        desk.setAgent(mallory, true);
        desk.approveVendor(mallory);
        vm.stopPrank();
        (uint256 perPayment, uint256 daily) = desk.limits(payer, address(fusd));
        assertEq(perPayment, 100e6); assertEq(daily, 250e6);
        assertFalse(desk.isAgent(payer, mallory));
        assertFalse(desk.approved(payer, mallory));
    }

    function test_agent_without_limits_pays_nothing() public {
        vm.startPrank(payer);
        desk.setAgent(agent, true); desk.setAgentSigner(agent, SIGNER);
        vm.stopPrank(); // named, but no limit set for fUSD
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.OverPerPaymentLimit.selector, 80e6, 0));
        _agentPays(_named("genuine_fusd"));
    }

    function test_agent_per_payment_limit() public {
        vm.startPrank(payer);
        desk.setAgent(agent, true); desk.setAgentSigner(agent, SIGNER);
        desk.setLimit(address(fusd), 79e6, 250e6);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.OverPerPaymentLimit.selector, 80e6, 79e6));
        _agentPays(_named("genuine_fusd"));
    }

    function test_agent_daily_limit_and_utc_day_reset() public {
        vm.startPrank(payer);
        desk.setAgent(agent, true); desk.setAgentSigner(agent, SIGNER);
        desk.setLimit(address(fusd), 100e6, 100e6);
        vm.stopPrank();
        uint256 midnight = 1795046400 + 86400; // 00:00:00 UTC
        vm.warp(midnight - 60); // 23:59:00 UTC
        _agentPays(_named("genuine_fusd")); // 80 of 100
        Case memory second = _named("tokenwell_genuine_fusd"); // 60 more: 140 > 100
        vm.warp(midnight - 1); // 23:59:59, same UTC day
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.OverDailyLimit.selector, 80e6, 60e6, 100e6));
        _agentPays(second);
        vm.warp(midnight); // one second later: a new UTC calendar day, not a rolling 24 h window
        assertEq(desk.remainingToday(payer, address(fusd)), 100e6);
        _agentPays(second);
        assertEq(fusd.balanceOf(tokenwell), 60e6);
    }

    function test_refused_agent_payments_do_not_count() public {
        _asAgent(); // 100 per payment, 250 per day
        // refused before the limits are looked at
        vm.expectRevert(InvoiceDeskV5.BadSignature.selector);
        _agentPays(_named("amount_edited"));
        assertEq(desk.remainingToday(payer, address(fusd)), 250e6);
        // refused AFTER the spend was recorded (the transfer fails): the record is rolled back with it
        vm.prank(payer);
        fusd.approve(address(desk), 79e6); // one short of the 80 fUSD invoice
        vm.expectRevert(InvoiceDeskV5.TransferFailed.selector);
        _agentPays(_named("genuine_fusd"));
        assertEq(desk.remainingToday(payer, address(fusd)), 250e6);
        // refused by the daily limit itself: nothing recorded either
        vm.prank(payer);
        fusd.approve(address(desk), type(uint256).max);
        vm.prank(payer);
        desk.setLimit(address(fusd), 100e6, 100e6);
        _agentPays(_named("genuine_fusd")); // 80 of 100
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.OverDailyLimit.selector, 80e6, 60e6, 100e6));
        _agentPays(_named("tokenwell_genuine_fusd"));
        assertEq(desk.remainingToday(payer, address(fusd)), 20e6);
    }

    function test_agent_cannot_pay_native_qor() public {
        _asAgent();
        Case memory c = _named("genuine_native_qor");
        vm.deal(agent, 1 ether);
        vm.prank(agent);
        vm.expectRevert(InvoiceDeskV5.AgentCannotPayNative.selector);
        desk.pay{value: c.amount}(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, _asig(c), VU);
    }

    function test_payer_in_person_is_not_bound_by_agent_limits() public {
        vm.prank(payer);
        desk.setLimit(address(fusd), 1, 1);
        _pay(_named("genuine_fusd"), 0); // the human approval path
        assertEq(fusd.balanceOf(hostline), 80e6);
    }

    /// For any limits the payer sets, the agent's 80 fUSD payment succeeds exactly when it fits both.
    function testFuzz_agent_limits_decide_exactly(uint256 perPayment, uint256 daily) public {
        perPayment = bound(perPayment, 0, 200e6);
        daily = bound(daily, 0, 200e6);
        vm.startPrank(payer);
        desk.setAgent(agent, true); desk.setAgentSigner(agent, SIGNER);
        desk.setLimit(address(fusd), perPayment, daily);
        vm.stopPrank();
        Case memory c = _named("genuine_fusd");
        if (c.amount > perPayment) vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.OverPerPaymentLimit.selector, c.amount, perPayment));
        else if (c.amount > daily) vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.OverDailyLimit.selector, 0, c.amount, daily));
        _agentPays(c);
        assertEq(fusd.balanceOf(hostline), c.amount <= perPayment && c.amount <= daily ? c.amount : 0);
    }

    // ------------------------------------------------------------------ coverage: the remaining paths

    function test_removed_vendor_is_refused() public {
        vm.prank(payer);
        desk.removeVendor(hostline);
        assertFalse(desk.approved(payer, hostline));
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.UnknownVendor.selector, hostline));
        _pay(_named("genuine_fusd"), 0);
    }

    function test_remaining_today_is_zero_once_the_daily_limit_is_used() public {
        vm.startPrank(payer);
        desk.setAgent(agent, true); desk.setAgentSigner(agent, SIGNER);
        desk.setLimit(address(fusd), 100e6, 80e6); // exactly one 80 fUSD invoice a day
        vm.stopPrank();
        _agentPays(_named("genuine_fusd"));
        assertEq(desk.remainingToday(payer, address(fusd)), 0);
        vm.prank(payer);
        desk.setLimit(address(fusd), 100e6, 50e6); // the company lowers the limit below what was spent
        assertEq(desk.remainingToday(payer, address(fusd)), 0);
    }

    function test_native_payment_to_a_vendor_that_refuses_funds_rolls_back() public {
        Case memory c = _named("genuine_native_qor");
        vm.etch(hostline, hex"60006000fd"); // revert(0, 0) on any call, including a plain value transfer
        vm.expectRevert(InvoiceDeskV5.TransferFailed.selector);
        _pay(c, c.amount);
        assertFalse(desk.paid(payer, hostline, c.id), "rolled back");
        assertEq(payer.balance, 10 ether);
    }

    // ------------------------------------------------------------------ what V4 adds: the agent's own ML-DSA-87 signature

    function test_agentMessage_matches_offchain_encoding() public view {
        string memory k = ".agentSigs.0x000000000000000000000000000000000000A9E7[0]";
        Case memory c = _case(0);
        assertEq(desk.agentMessage(c.payer, agent, keccak256(c.message), keccak256(c.signature), VU), vm.parseJsonBytes(fx, string.concat(k, ".message")));
        assertEq(keccak256(c.message), keccak256(desk.invoiceMessage(c.payer, c.vendor, c.token, c.amount, c.id, c.dueBy)));
    }

    function test_a_stolen_agent_key_alone_pays_nothing() public {
        _asAgent();
        Case memory c = _named("genuine_fusd");
        vm.prank(agent); // the agent account, as reached with its (classical) key: no ML-DSA-87 signature
        vm.expectRevert(InvoiceDeskV5.BadAgentSignature.selector);
        desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, "", VU);
        assertEq(fusd.balanceOf(hostline), 0);
    }

    function test_agent_signature_from_another_key_is_refused() public {
        _asAgent();
        Case memory c = _named("genuine_fusd");
        vm.prank(agent);
        vm.expectRevert(InvoiceDeskV5.BadAgentSignature.selector);
        desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, vm.parseJsonBytes(fx, ".foreign.signature"), VU);
    }

    function test_agent_signature_is_bound_to_one_invoice() public {
        _asAgent();
        Case memory c = _named("genuine_fusd");
        bytes memory other = _asig(_named("tokenwell_genuine_fusd")); // a real agent signature, for another invoice
        vm.prank(agent);
        vm.expectRevert(InvoiceDeskV5.BadAgentSignature.selector);
        desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, other, VU);
    }

    function test_agent_without_a_named_signer_pays_nothing() public {
        vm.startPrank(payer);
        desk.setAgent(agent, true); desk.setLimit(address(fusd), 100e6, 250e6);
        desk.setAgentSigner(agent, address(0));
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.AgentSignerNotSet.selector, agent));
        _agentPays(_named("genuine_fusd"));
    }

    function test_agent_signer_key_must_be_proven_ml_dsa_87() public {
        _asAgent();
        PqcKeyStatusStandIn(STATUS).set(SIGNER, true, 1, vm.parseJsonBytes(fx, ".keys.agentsigner"), false);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.AgentKeyNotProven.selector, SIGNER));
        _agentPays(_named("genuine_fusd"));
    }

    function test_the_payer_in_person_needs_no_agent_signature() public {
        Case memory c = _named("genuine_fusd");
        vm.prank(payer);
        desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, "", VU);
        assertEq(fusd.balanceOf(hostline), 80e6);
    }

    function test_only_the_payer_names_its_agents_signer() public {
        _asAgent();
        vm.prank(agent);
        desk.setAgentSigner(agent, mallory); // writes the agent's own (empty) payer entry
        assertEq(desk.agentSigner(payer, agent), SIGNER);
        _agentPays(_named("genuine_fusd")); // still the real signer
        assertEq(fusd.balanceOf(hostline), 80e6);
    }

    /// The agent's signature for one invoice authorises that invoice only: not a corrected amount, not a
    /// second invoice for the same amount, not a reissue in another token, each genuinely signed by the vendor.
    function test_agent_signature_binds_amount_invoice_and_token() public {
        _asAgent();
        MockToken(otherToken).mint(payer, 0); // the other token exists and has an allowance (setUp)
        bytes memory forGenuine = _asig(_named("genuine_fusd"));
        for (uint256 i = 0; i < 3; i++) {
            Case memory x = _extra(i);
            vm.prank(agent);
            vm.expectRevert(InvoiceDeskV5.BadAgentSignature.selector);
            desk.pay(x.payer, x.token, payable(x.vendor), x.amount, x.id, x.dueBy, x.signature, forGenuine, VU);
        }
        _agentPays(_named("genuine_fusd")); // the one it signed: paid
        assertEq(fusd.balanceOf(hostline), 80e6);
    }

    /// Another agent of the same payer, with the same signer, cannot reuse the first agent's signature.
    function test_agent_signature_binds_the_agent() public {
        _asAgent();
        address agent2 = address(0xB0B2);
        vm.startPrank(payer); desk.setAgent(agent2, true); desk.setAgentSigner(agent2, SIGNER); vm.stopPrank();
        Case memory c = _named("genuine_fusd");
        vm.prank(agent2);
        vm.expectRevert(InvoiceDeskV5.BadAgentSignature.selector);
        desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, _asig(c), VU);
    }

    // ------------------------------------------------------------------ what V5 adds: the agent signs the whole invoice, and a deadline

    /// The agent signer's signature for extra i (test/fixtures.mjs, `extraAgentSigs`).
    function _xsig(uint256 i) internal view returns (bytes memory) { return vm.parseJsonBytes(fx, string.concat(".extraAgentSigs[", vm.toString(i), "].signature")); }
    function _agentPaysWith(Case memory c, bytes memory agentSig, uint64 validUntil) internal {
        vm.prank(agent);
        desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, agentSig, validUntil);
    }

    function test_bindings_fixture_answers_as_real_mldsa87() public view {
        bytes memory signerKey = vm.parseJsonBytes(fx, ".keys.agentsigner");
        bool[4] memory expected = [false, false, false, true];
        for (uint256 i = 0; i < 4; i++) {
            (bool ok, bytes memory ret) = VERIFY.staticcall(abi.encodeWithSignature("pqcVerify(bytes,bytes,bytes)", signerKey, vm.parseJsonBytes(fx, _b(i, "agentSignature")), vm.parseJsonBytes(fx, _b(i, "message"))));
            assertTrue(ok);
            assertEq(abi.decode(ret, (bool)), expected[i], vm.parseJsonString(fx, _b(i, "name")));
            // each message is exactly what the desk builds from what was presented
            Case memory c = _named("genuine_fusd");
            if (i == 1) c = _extra(3);
            assertEq(desk.agentMessage(c.payer, agent, keccak256(c.message), keccak256(c.signature), uint64(vm.parseJsonUint(fx, _b(i, "validUntil")))), vm.parseJsonBytes(fx, _b(i, "message")));
        }
    }

    function test_agent_signature_expires() public {
        _asAgent();
        Case memory c = _named("genuine_fusd");
        assertEq(vm.parseJsonUint(fx, _b(3, "at")), uint256(VU) + 1);
        vm.warp(uint256(VU) + 1); // the agent signature itself still verifies (bindings[3].valid): refused by time
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.AgentSignatureExpired.selector, VU));
        _agentPays(c);
        // checked before the signature: an expired payment is refused the same way with no signature at all
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.AgentSignatureExpired.selector, VU));
        _agentPaysWith(c, "", VU);
        assertEq(fusd.balanceOf(hostline), 0);
        assertFalse(desk.paid(payer, hostline, c.id));
        assertEq(desk.remainingToday(payer, address(fusd)), 250e6);
    }

    function test_agent_signature_still_pays_exactly_at_validUntil() public {
        _asAgent();
        Case memory x = _extra(3); // Hostline's genuine reissue, due 30 days after validUntil's week
        assertGt(x.dueBy, VU);
        vm.warp(VU);
        _agentPaysWith(x, _xsig(3), VU);
        assertEq(fusd.balanceOf(hostline), 80e6);
    }

    /// A refused agent payment's signature dies at its deadline: once the refusal no longer holds, it pays nothing.
    function test_a_refused_agent_signature_cannot_be_replayed_after_validUntil() public {
        vm.startPrank(payer);
        desk.setAgent(agent, true); desk.setAgentSigner(agent, SIGNER);
        desk.setLimit(address(fusd), 79e6, 250e6);
        vm.stopPrank();
        Case memory x = _extra(3);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.OverPerPaymentLimit.selector, 80e6, 79e6));
        _agentPaysWith(x, _xsig(3), VU);
        vm.prank(payer);
        desk.setLimit(address(fusd), 100e6, 250e6); // the refusal no longer holds
        vm.warp(uint256(VU) + 1);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.AgentSignatureExpired.selector, VU));
        _agentPaysWith(x, _xsig(3), VU);
        assertEq(fusd.balanceOf(hostline), 0);
    }

    /// The agent signature made for a forged copy (same fields, a bad vendor signature) cannot pay the
    /// genuine invoice with those fields: it binds the vendor's signature.
    function test_forged_copy_agent_signature_cannot_pay_the_genuine_invoice() public {
        _asAgent();
        Case memory forged = _named("forged_by_mallory_as_hostline");
        Case memory g = _named("genuine_fusd");
        assertEq(keccak256(forged.message), keccak256(g.message), "same fields");
        bytes memory forForged = vm.parseJsonBytes(fx, _b(0, "agentSignature"));
        assertEq(forForged, _asig(forged));
        vm.expectRevert(InvoiceDeskV5.BadSignature.selector); // what it was made for: the forged copy
        _agentPaysWith(forged, forForged, VU);
        vm.expectRevert(InvoiceDeskV5.BadAgentSignature.selector); // the genuine invoice, same fields
        _agentPaysWith(g, forForged, VU);
        assertEq(fusd.balanceOf(hostline), 0);
        _agentPays(g); // with its own agent signature: paid
        assertEq(fusd.balanceOf(hostline), 80e6);
    }

    /// The vendor reissues the same invoice with a later due date: the old agent signature does not pay it.
    function test_due_date_reissue_cannot_reuse_the_old_agent_signature() public {
        _asAgent();
        Case memory g = _named("genuine_fusd");
        Case memory x = _extra(3);
        assertTrue(x.amount == g.amount && x.id == g.id && x.token == g.token && x.dueBy > g.dueBy);
        vm.warp(uint256(g.dueBy) + 1);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV5.PastDue.selector, g.dueBy));
        _agentPays(g); // the original: past due
        vm.expectRevert(InvoiceDeskV5.BadAgentSignature.selector);
        _agentPaysWith(x, _asig(g), VU); // the reissue, with the original's agent signature (bindings[1])
        assertEq(vm.parseJsonBytes(fx, _b(1, "agentSignature")), _asig(g));
        _agentPaysWith(x, _xsig(3), VU); // with an agent signature for the reissue itself: paid
        assertEq(fusd.balanceOf(hostline), 80e6);
    }

    function test_changing_validUntil_in_calldata_breaks_the_signature() public {
        _asAgent();
        Case memory c = _named("genuine_fusd");
        assertEq(vm.parseJsonUint(fx, _b(2, "validUntil")), uint256(VU) + 1);
        vm.expectRevert(InvoiceDeskV5.BadAgentSignature.selector);
        _agentPaysWith(c, _asig(c), VU + 1); // extended (bindings[2])
        vm.expectRevert(InvoiceDeskV5.BadAgentSignature.selector);
        _agentPaysWith(c, _asig(c), VU - 1); // shortened
        _agentPaysWith(c, _asig(c), VU);
        assertEq(fusd.balanceOf(hostline), 80e6);
    }

    function testFuzz_any_other_validUntil_is_refused(uint64 validUntil) public {
        _asAgent();
        Case memory c = _named("genuine_fusd");
        vm.assume(validUntil != VU && validUntil >= block.timestamp);
        vm.expectRevert(InvoiceDeskV5.BadAgentSignature.selector);
        _agentPaysWith(c, _asig(c), validUntil);
    }

    /// The payer in person signs nothing as an agent: validUntil is ignored, whatever it says.
    function testFuzz_the_payer_ignores_validUntil(uint64 validUntil) public {
        Case memory c = _named("genuine_fusd");
        vm.prank(payer);
        desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, "", validUntil);
        assertEq(fusd.balanceOf(hostline), 80e6);
    }

    function test_the_payer_ignores_validUntil_even_long_after_it() public {
        Case memory c = _named("genuine_fusd");
        vm.warp(uint256(VU) + 365 days);
        vm.prank(payer);
        desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, "", 0);
        assertEq(fusd.balanceOf(hostline), 80e6);
    }
}
