// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {InvoiceDeskV2} from "../contracts/InvoiceDeskV2.sol";
import {PqcVerifyStandIn, PqcKeyStatusStandIn} from "./InvoiceDesk.t.sol";

/// Minimal fUSD stand-in: standard ERC-20 transferFrom/allowance semantics, 6 decimals.
contract MockToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transfer(address to, uint256 a) external returns (bool) { balanceOf[msg.sender] -= a; balanceOf[to] += a; return true; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        allowance[f][msg.sender] -= a; balanceOf[f] -= a; balanceOf[to] += a; return true;
    }
}

/// A token that reports failure instead of reverting.
contract FalseToken {
    function transferFrom(address, address, uint256) external pure returns (bool) { return false; }
}

contract InvoiceDeskV2Test is Test {
    address constant VERIFY = 0x0000000000000000000000000000000000000a01;
    address constant STATUS = 0x0000000000000000000000000000000000000a02;
    uint256 constant N = 13;
    string fx;
    InvoiceDeskV2 desk;
    MockToken fusd;
    address payer; address payer2; address hostline; address tokenwell; address mallory; address otherToken;

    event InvoicePaid(address indexed payer, address indexed vendor, bytes32 indexed id, address token, uint256 amount, address by);

    struct Case { bytes pubkey; bytes signature; bytes message; bool valid; address payer; address vendor; address token; uint256 amount; bytes32 id; uint64 dueBy; }

    function setUp() public {
        fx = vm.readFile("test/fixtures/mldsa-v2.json");
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
        PqcKeyStatusStandIn(STATUS).set(hostline, true, 1, vm.parseJsonBytes(fx, ".keys.hostline"), true);
        PqcKeyStatusStandIn(STATUS).set(tokenwell, true, 1, vm.parseJsonBytes(fx, ".keys.tokenwell"), true);
        PqcKeyStatusStandIn(STATUS).set(mallory, true, 1, vm.parseJsonBytes(fx, ".keys.mallory"), true);

        deployCodeTo("MockToken", vm.parseJsonAddress(fx, ".tokens.fusd"));
        fusd = MockToken(vm.parseJsonAddress(fx, ".tokens.fusd"));
        deployCodeTo("MockToken", otherToken);
        deployCodeTo("InvoiceDeskV2.sol:InvoiceDeskV2", vm.parseJsonAddress(fx, ".addresses.desk"));
        desk = InvoiceDeskV2(vm.parseJsonAddress(fx, ".addresses.desk"));

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
    function _named(string memory name) internal view returns (Case memory) {
        for (uint256 i = 0; i < N; i++) if (keccak256(bytes(vm.parseJsonString(fx, _k(i, "name")))) == keccak256(bytes(name))) return _case(i);
        revert(string.concat("no fixture ", name));
    }
    function _pay(Case memory c, uint256 value) internal {
        vm.prank(c.payer);
        desk.pay{value: value}(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
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
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.WrongAmount.selector, 1, 0));
        _pay(c, 1);
    }

    function test_the_currency_is_signed() public {
        vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
        _pay(_named("paid_in_qor_instead"), 80e6);
        vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
        _pay(_named("paid_in_other_token"), 0);
    }

    function test_refuses_every_tampering() public {
        string[6] memory names = ["forged_by_mallory_as_hostline", "amount_edited", "payee_swapped_to_tokenwell", "due_extended", "one_bit_flipped", "paid_in_other_token"];
        for (uint256 i = 0; i < names.length; i++) {
            Case memory c = _named(names[i]);
            vm.prank(payer);
            vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
            desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
        }
        assertEq(fusd.balanceOf(payer), 1000e6);
    }

    function test_refuses_on_another_desk() public {
        address other = vm.parseJsonAddress(fx, ".addresses.desk2");
        deployCodeTo("InvoiceDeskV2.sol:InvoiceDeskV2", other);
        vm.startPrank(payer);
        InvoiceDeskV2(other).approveVendor(hostline);
        fusd.approve(other, 600e6);
        Case memory c = _named("genuine_fusd"); // signed for the first desk
        vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
        InvoiceDeskV2(other).pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
        vm.stopPrank();
    }

    function test_refuses_other_payer() public {
        vm.prank(payer2);
        desk.approveVendor(hostline);
        Case memory c = _named("other_payer"); // fields name payer2, signature is for payer
        vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
        _pay(c, 0);
    }

    function test_refuses_unknown_vendor_even_with_valid_signature() public {
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.UnknownVendor.selector, mallory));
        _pay(_named("mallory_own_invoice"), 0);
    }

    function test_refuses_replay_and_edited_copy_is_still_a_forgery() public {
        Case memory c = _named("genuine_fusd");
        _pay(c, 0);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.AlreadyPaid.selector, c.id));
        _pay(c, 0);
        vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
        _pay(_named("amount_edited"), 0);
    }

    function test_refuses_past_due() public {
        Case memory c = _named("genuine_fusd");
        vm.warp(uint256(c.dueBy) + 1);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.PastDue.selector, c.dueBy));
        _pay(c, 0);
    }

    function test_allowance_is_a_cap() public {
        vm.prank(payer);
        fusd.approve(address(desk), 79e6);
        vm.expectRevert(InvoiceDeskV2.TransferFailed.selector);
        _pay(_named("genuine_fusd"), 0);
        assertFalse(desk.paid(payer, _named("genuine_fusd").id), "rolled back");
    }

    function test_insufficient_balance_rolls_back() public {
        vm.prank(payer);
        fusd.transfer(address(1), 950e6);
        vm.expectRevert(InvoiceDeskV2.TransferFailed.selector);
        _pay(_named("genuine_fusd"), 0);
    }

    function test_token_without_code_is_refused() public {
        Case memory c = _named("genuine_fusd");
        vm.etch(c.token, "");
        vm.expectRevert(InvoiceDeskV2.TransferFailed.selector);
        _pay(c, 0);
    }

    function test_token_returning_false_is_refused() public {
        Case memory c = _named("genuine_fusd");
        vm.etch(c.token, type(FalseToken).runtimeCode);
        vm.expectRevert(InvoiceDeskV2.TransferFailed.selector);
        _pay(c, 0);
    }

    function test_vendor_key_must_be_proven_ml_dsa_87() public {
        PqcKeyStatusStandIn(STATUS).set(hostline, true, 1, vm.parseJsonBytes(fx, ".keys.hostline"), false);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.VendorKeyNotProven.selector, hostline));
        _pay(_named("genuine_fusd"), 0);
    }

    function test_vendor_key_of_another_algorithm_or_unregistered_is_refused() public {
        bytes memory pk = vm.parseJsonBytes(fx, ".keys.hostline");
        PqcKeyStatusStandIn(STATUS).set(hostline, true, 2, pk, true); // registered and proven, but not ML-DSA-87
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.VendorKeyNotProven.selector, hostline));
        _pay(_named("genuine_fusd"), 0);
        PqcKeyStatusStandIn(STATUS).set(hostline, false, 1, pk, true); // not registered
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.VendorKeyNotProven.selector, hostline));
        _pay(_named("genuine_fusd"), 0);
    }

    function test_vendor_key_rotated_old_invoices_no_longer_verify() public {
        // Hostline's registered key is replaced (here by Tokenwell's): invoices signed with the old key now fail.
        PqcKeyStatusStandIn(STATUS).set(hostline, true, 1, vm.parseJsonBytes(fx, ".keys.tokenwell"), true);
        vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
        _pay(_named("genuine_fusd"), 0);
    }

    function testFuzz_any_other_amount_is_refused(uint256 amount) public {
        Case memory c = _named("genuine_fusd");
        vm.assume(amount != c.amount && amount <= 600e6);
        vm.prank(payer);
        vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
        desk.pay(c.payer, c.token, payable(c.vendor), amount, c.id, c.dueBy, c.signature);
    }

    function testFuzz_any_other_token_is_refused(address token) public {
        Case memory c = _named("genuine_fusd");
        vm.assume(token != c.token);
        vm.prank(payer);
        vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
        desk.pay(c.payer, token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
    }

    // ------------------------------------------------------------------ the agent: its own account, the payer's money

    address agent = address(0xA9E7);

    function _asAgent() internal {
        vm.startPrank(payer);
        desk.setAgent(agent, true);
        desk.setLimit(address(fusd), 100e6, 250e6);
        vm.stopPrank();
    }
    function _agentPays(Case memory c) internal {
        vm.prank(agent);
        desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
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
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.NotPayersAgent.selector, agent));
        _agentPays(c);
    }

    function test_removing_the_agent_is_a_kill_switch() public {
        _asAgent();
        vm.prank(payer);
        desk.setAgent(agent, false);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.NotPayersAgent.selector, agent));
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
        vm.prank(payer);
        desk.setAgent(agent, true); // named, but no limit set for fUSD
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.OverPerPaymentLimit.selector, 80e6, 0));
        _agentPays(_named("genuine_fusd"));
    }

    function test_agent_per_payment_limit() public {
        vm.startPrank(payer);
        desk.setAgent(agent, true);
        desk.setLimit(address(fusd), 79e6, 250e6);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.OverPerPaymentLimit.selector, 80e6, 79e6));
        _agentPays(_named("genuine_fusd"));
    }

    function test_agent_daily_limit_and_utc_day_reset() public {
        vm.startPrank(payer);
        desk.setAgent(agent, true);
        desk.setLimit(address(fusd), 100e6, 100e6);
        vm.stopPrank();
        uint256 midnight = 1795046400 + 86400; // 00:00:00 UTC
        vm.warp(midnight - 60); // 23:59:00 UTC
        _agentPays(_named("genuine_fusd")); // 80 of 100
        Case memory second = _named("tokenwell_genuine_fusd"); // 60 more: 140 > 100
        vm.warp(midnight - 1); // 23:59:59, same UTC day
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.OverDailyLimit.selector, 80e6, 60e6, 100e6));
        _agentPays(second);
        vm.warp(midnight); // one second later: a new UTC calendar day, not a rolling 24 h window
        assertEq(desk.remainingToday(payer, address(fusd)), 100e6);
        _agentPays(second);
        assertEq(fusd.balanceOf(tokenwell), 60e6);
    }

    function test_refused_agent_payments_do_not_count() public {
        _asAgent(); // 100 per payment, 250 per day
        // refused before the limits are looked at
        vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
        _agentPays(_named("amount_edited"));
        assertEq(desk.remainingToday(payer, address(fusd)), 250e6);
        // refused AFTER the spend was recorded (the transfer fails): the record is rolled back with it
        vm.prank(payer);
        fusd.approve(address(desk), 79e6); // one short of the 80 fUSD invoice
        vm.expectRevert(InvoiceDeskV2.TransferFailed.selector);
        _agentPays(_named("genuine_fusd"));
        assertEq(desk.remainingToday(payer, address(fusd)), 250e6);
        // refused by the daily limit itself: nothing recorded either
        vm.prank(payer);
        fusd.approve(address(desk), type(uint256).max);
        vm.prank(payer);
        desk.setLimit(address(fusd), 100e6, 100e6);
        _agentPays(_named("genuine_fusd")); // 80 of 100
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.OverDailyLimit.selector, 80e6, 60e6, 100e6));
        _agentPays(_named("tokenwell_genuine_fusd"));
        assertEq(desk.remainingToday(payer, address(fusd)), 20e6);
    }

    function test_agent_cannot_pay_native_qor() public {
        _asAgent();
        Case memory c = _named("genuine_native_qor");
        vm.deal(agent, 1 ether);
        vm.prank(agent);
        vm.expectRevert(InvoiceDeskV2.AgentCannotPayNative.selector);
        desk.pay{value: c.amount}(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
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
        desk.setAgent(agent, true);
        desk.setLimit(address(fusd), perPayment, daily);
        vm.stopPrank();
        Case memory c = _named("genuine_fusd");
        if (c.amount > perPayment) vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.OverPerPaymentLimit.selector, c.amount, perPayment));
        else if (c.amount > daily) vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.OverDailyLimit.selector, 0, c.amount, daily));
        _agentPays(c);
        assertEq(fusd.balanceOf(hostline), c.amount <= perPayment && c.amount <= daily ? c.amount : 0);
    }

    // ------------------------------------------------------------------ coverage: the remaining paths

    function test_removed_vendor_is_refused() public {
        vm.prank(payer);
        desk.removeVendor(hostline);
        assertFalse(desk.approved(payer, hostline));
        vm.expectRevert(abi.encodeWithSelector(InvoiceDeskV2.UnknownVendor.selector, hostline));
        _pay(_named("genuine_fusd"), 0);
    }

    function test_remaining_today_is_zero_once_the_daily_limit_is_used() public {
        vm.startPrank(payer);
        desk.setAgent(agent, true);
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
        vm.expectRevert(InvoiceDeskV2.TransferFailed.selector);
        _pay(c, c.amount);
        assertFalse(desk.paid(payer, c.id), "rolled back");
        assertEq(payer.balance, 10 ether);
    }
}
