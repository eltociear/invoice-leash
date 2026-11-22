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
    uint256 constant N = 12;
    string fx;
    InvoiceDeskV2 desk;
    MockToken fusd;
    address payer; address payer2; address hostline; address tokenwell; address mallory; address otherToken;

    event InvoicePaid(address indexed payer, address indexed vendor, bytes32 indexed id, address token, uint256 amount);

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
        desk.pay{value: value}(c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
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
        emit InvoicePaid(c.payer, c.vendor, c.id, c.token, c.amount);
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
            desk.pay(c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
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
        InvoiceDeskV2(other).pay(c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
        vm.stopPrank();
    }

    function test_refuses_other_payer() public {
        vm.prank(payer2);
        desk.approveVendor(hostline);
        Case memory c = _named("other_payer");
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

    function testFuzz_any_other_amount_is_refused(uint256 amount) public {
        Case memory c = _named("genuine_fusd");
        vm.assume(amount != c.amount && amount <= 600e6);
        vm.prank(payer);
        vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
        desk.pay(c.token, payable(c.vendor), amount, c.id, c.dueBy, c.signature);
    }

    function testFuzz_any_other_token_is_refused(address token) public {
        Case memory c = _named("genuine_fusd");
        vm.assume(token != c.token);
        vm.prank(payer);
        vm.expectRevert(InvoiceDeskV2.BadSignature.selector);
        desk.pay(token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
    }
}
