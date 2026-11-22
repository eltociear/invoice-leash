// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {InvoiceDesk} from "../contracts/InvoiceDesk.sol";

/// Stand-in for QoreChain's pqcVerify precompile (0x…0a01). It answers from test/fixtures/mldsa.json,
/// where every (pubkey, signature, message) tuple was checked with REAL ML-DSA-87 by
/// test/fixtures.mjs. Anything not in the file is false (fail closed).
contract PqcVerifyStandIn {
    mapping(bytes32 => bool) public valid;
    function record(bytes calldata pubkey, bytes calldata signature, bytes calldata message, bool ok) external {
        valid[keccak256(abi.encode(keccak256(pubkey), keccak256(signature), keccak256(message)))] = ok;
    }
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message) external view returns (bool) {
        return valid[keccak256(abi.encode(keccak256(pubkey), keccak256(signature), keccak256(message)))];
    }
}

/// Stand-in for pqcKeyStatus (0x…0a02): per address, as the chain's PQC module would report it.
contract PqcKeyStatusStandIn {
    struct K { bool registered; uint8 alg; bytes pubkey; bool proven; }
    mapping(address => K) internal k;
    function set(address a, bool registered, uint8 alg, bytes calldata pubkey, bool proven) external { k[a] = K(registered, alg, pubkey, proven); }
    function pqcKeyStatus(address a) external view returns (bool, uint8, bytes memory, bool) { K storage x = k[a]; return (x.registered, x.alg, x.pubkey, x.proven); }
}

/// A vendor whose receive() tries to pay itself the same invoice again before accepting.
contract ReentrantVendor {
    InvoiceDesk public desk; bytes public payload; bool public reentered; bool public reentrySucceeded;
    function arm(InvoiceDesk d, bytes calldata p) external { desk = d; payload = p; }
    receive() external payable {
        if (reentered) return;
        reentered = true;
        (bool ok,) = address(desk).call{value: msg.value}(payload);
        reentrySucceeded = ok;
    }
}

contract RevertingVendor { receive() external payable { revert("no"); } }

contract InvoiceDeskTest is Test {
    address constant VERIFY = 0x0000000000000000000000000000000000000a01;
    address constant STATUS = 0x0000000000000000000000000000000000000a02;
    string fx;
    InvoiceDesk desk;
    address payer; address payer2; address hostline; address tokenwell; address mallory;

    event InvoicePaid(address indexed payer, address indexed vendor, bytes32 indexed id, uint256 amount);

    struct Case { bytes pubkey; bytes signature; bytes message; bool valid; address payer; address vendor; uint256 amount; bytes32 id; uint64 dueBy; address desk; }

    function setUp() public {
        fx = vm.readFile("test/fixtures/mldsa.json");
        vm.chainId(vm.parseJsonUint(fx, ".chainId"));
        payer = vm.parseJsonAddress(fx, ".addresses.payer");
        payer2 = vm.parseJsonAddress(fx, ".addresses.payer2");
        hostline = vm.parseJsonAddress(fx, ".addresses.hostline");
        tokenwell = vm.parseJsonAddress(fx, ".addresses.tokenwell");
        mallory = vm.parseJsonAddress(fx, ".addresses.mallory");

        vm.etch(VERIFY, address(new PqcVerifyStandIn()).code);
        vm.etch(STATUS, address(new PqcKeyStatusStandIn()).code);
        // Teach the verify stand-in every real ML-DSA-87 answer in the fixture file.
        for (uint256 i = 0; i < 14; i++) {
            Case memory c = _case(i);
            PqcVerifyStandIn(VERIFY).record(c.pubkey, c.signature, c.message, c.valid);
        }
        _setKey(hostline, "hostline", true, 1, true);
        _setKey(tokenwell, "tokenwell", true, 1, true);
        _setKey(mallory, "mallory", true, 1, true); // a perfectly valid key; she is just not a vendor

        deployCodeTo("InvoiceDesk.sol:InvoiceDesk", vm.parseJsonAddress(fx, ".addresses.desk"));
        desk = InvoiceDesk(vm.parseJsonAddress(fx, ".addresses.desk"));
        vm.startPrank(payer);
        desk.approveVendor(hostline);
        desk.approveVendor(tokenwell);
        vm.stopPrank();
        vm.deal(payer, 100 ether);
        vm.deal(payer2, 100 ether);
        vm.warp(1795000000); // 2026-11, before every fixture's due date
    }

    // ------------------------------------------------------------------ helpers

    function _k(uint256 i, string memory f) internal pure returns (string memory) { return string.concat(".cases[", vm.toString(i), "].", f); }
    function _case(uint256 i) internal view returns (Case memory c) {
        c.pubkey = vm.parseJsonBytes(fx, _k(i, "pubkey"));
        c.signature = vm.parseJsonBytes(fx, _k(i, "signature"));
        c.message = vm.parseJsonBytes(fx, _k(i, "message"));
        c.valid = vm.parseJsonBool(fx, _k(i, "valid"));
        if (keccak256(bytes(vm.parseJsonString(fx, _k(i, "name")))) != keccak256("message_for_chain_1")) {
            c.payer = vm.parseJsonAddress(fx, _k(i, "payer"));
            c.vendor = vm.parseJsonAddress(fx, _k(i, "vendor"));
            c.amount = vm.parseJsonUint(fx, _k(i, "amount"));
            c.id = vm.parseJsonBytes32(fx, _k(i, "id"));
            c.dueBy = uint64(vm.parseJsonUint(fx, _k(i, "dueBy")));
            c.desk = vm.parseJsonAddress(fx, _k(i, "desk"));
        }
    }
    function _named(string memory name) internal view returns (Case memory) {
        for (uint256 i = 0; i < 14; i++) if (keccak256(bytes(vm.parseJsonString(fx, _k(i, "name")))) == keccak256(bytes(name))) return _case(i);
        revert(string.concat("no fixture ", name));
    }
    function _setKey(address who, string memory name, bool registered, uint8 alg, bool proven) internal {
        PqcKeyStatusStandIn(STATUS).set(who, registered, alg, vm.parseJsonBytes(fx, string.concat(".keys.", name)), proven);
    }
    function _pay(address from, Case memory c, uint256 value) internal {
        vm.prank(from);
        desk.pay{value: value}(payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
    }
    function _pay(Case memory c) internal { _pay(c.payer, c, c.amount); }

    // ------------------------------------------------------------------ the stand-in itself

    /// Every fixture tuple: the stand-in's answer is exactly what real ML-DSA-87 said.
    function test_standIn_answers_as_real_mldsa87() public view {
        for (uint256 i = 0; i < 14; i++) {
            Case memory c = _case(i);
            (bool ok, bytes memory ret) = VERIFY.staticcall(abi.encodeWithSignature("pqcVerify(bytes,bytes,bytes)", c.pubkey, c.signature, c.message));
            assertTrue(ok);
            assertEq(abi.decode(ret, (bool)), c.valid, vm.parseJsonString(fx, _k(i, "name")));
        }
    }

    /// The bytes pay() verifies are the bytes vendors sign off chain (lib/invoices.mjs).
    function test_invoiceMessage_matches_offchain_encoding() public view {
        Case memory c = _named("genuine");
        assertEq(desk.invoiceMessage(c.payer, c.vendor, c.amount, c.id, c.dueBy), c.message);
        assertEq(c.message.length, 256);
    }

    // ------------------------------------------------------------------ paying

    function test_pays_a_genuine_invoice() public {
        Case memory c = _named("genuine");
        uint256 before = hostline.balance;
        vm.expectEmit(true, true, true, true, address(desk));
        emit InvoicePaid(c.payer, c.vendor, c.id, c.amount);
        _pay(c);
        assertEq(hostline.balance - before, c.amount);
        assertTrue(desk.paid(c.payer, c.id));
        assertEq(address(desk).balance, 0, "the desk never holds money");
    }

    function test_two_vendors_two_invoices() public {
        _pay(_named("genuine"));
        _pay(_named("tokenwell_genuine"));
        assertEq(tokenwell.balance, 0.5 ether);
    }

    // ------------------------------------------------------------------ refusals, in pay()'s order

    function test_refuses_unknown_vendor_even_with_a_valid_signature() public {
        Case memory c = _named("mallory_own_invoice");
        assertTrue(c.valid, "her signature IS valid ML-DSA-87");
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.UnknownVendor.selector, mallory));
        _pay(c);
    }

    function test_refuses_forgery_signed_by_another_registered_key() public {
        vm.expectRevert(InvoiceDesk.BadSignature.selector);
        _pay(_named("forged_by_mallory_as_hostline"));
    }

    function test_refuses_every_tampering() public {
        string[8] memory names = ["amount_edited", "amount_plus_one_wei", "payee_swapped_to_tokenwell", "due_extended",
            "other_invoice_id", "one_bit_flipped", "forged_by_mallory_as_hostline", "genuine"];
        for (uint256 i = 0; i < 7; i++) {
            Case memory c = _named(names[i]);
            Case memory g = _named("genuine");
            // Present the tampered fields with the genuine signature (or the forged one), as an attacker would.
            vm.prank(payer);
            vm.expectRevert(InvoiceDesk.BadSignature.selector);
            desk.pay{value: c.amount}(payable(c.vendor), c.amount, c.id, c.dueBy, c.signature);
            assertFalse(desk.paid(payer, g.id));
        }
    }

    function test_refuses_the_invoice_charged_to_another_payer() public {
        vm.prank(payer2);
        desk.approveVendor(hostline);
        Case memory g = _named("genuine"); // signed for payer
        vm.expectRevert(InvoiceDesk.BadSignature.selector);
        _pay(payer2, g, g.amount);
    }

    function test_refuses_on_another_chain() public {
        vm.chainId(1);
        vm.expectRevert(InvoiceDesk.BadSignature.selector);
        _pay(_named("genuine"));
    }

    function test_refuses_on_another_desk() public {
        address other = vm.parseJsonAddress(fx, ".addresses.desk2");
        deployCodeTo("InvoiceDesk.sol:InvoiceDesk", other);
        vm.prank(payer);
        InvoiceDesk(other).approveVendor(hostline);
        Case memory g = _named("genuine"); // signed for the first desk
        vm.prank(payer);
        vm.expectRevert(InvoiceDesk.BadSignature.selector);
        InvoiceDesk(other).pay{value: g.amount}(payable(g.vendor), g.amount, g.id, g.dueBy, g.signature);
    }

    function test_refuses_replay() public {
        Case memory g = _named("genuine");
        _pay(g);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.AlreadyPaid.selector, g.id));
        _pay(g);
    }

    /// An edited copy of a PAID invoice is reported as the forgery it is, not as a harmless duplicate.
    function test_edited_copy_of_paid_invoice_is_BadSignature_not_AlreadyPaid() public {
        _pay(_named("genuine"));
        Case memory e = _named("amount_edited");
        vm.expectRevert(InvoiceDesk.BadSignature.selector);
        _pay(e);
    }

    function test_refuses_past_due() public {
        Case memory g = _named("genuine");
        vm.warp(uint256(g.dueBy) + 1);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.PastDue.selector, g.dueBy));
        _pay(g);
    }

    function test_pays_on_the_due_second() public {
        Case memory g = _named("genuine");
        vm.warp(g.dueBy);
        _pay(g);
        assertTrue(desk.paid(g.payer, g.id));
    }

    function test_refuses_wrong_amount_sent() public {
        Case memory g = _named("genuine");
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.WrongAmount.selector, g.amount - 1, g.amount));
        _pay(payer, g, g.amount - 1);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.WrongAmount.selector, g.amount + 1, g.amount));
        _pay(payer, g, g.amount + 1);
    }

    // ------------------------------------------------------------------ the vendor's key, read live from the PQC module

    function test_refuses_vendor_key_not_registered() public {
        _setKey(hostline, "hostline", false, 1, true);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.VendorKeyNotProven.selector, hostline));
        _pay(_named("genuine"));
    }

    function test_refuses_vendor_key_without_proof_of_possession() public {
        _setKey(hostline, "hostline", true, 1, false);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.VendorKeyNotProven.selector, hostline));
        _pay(_named("genuine"));
    }

    function test_refuses_vendor_key_of_another_algorithm() public {
        _setKey(hostline, "hostline", true, 2, true);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.VendorKeyNotProven.selector, hostline));
        _pay(_named("genuine"));
    }

    /// The key is read at payment time: a vendor that rotates to a new key cannot be paid on old signatures.
    function test_uses_the_key_registered_now() public {
        PqcKeyStatusStandIn(STATUS).set(hostline, true, 1, vm.parseJsonBytes(fx, ".keys.tokenwell"), true);
        vm.expectRevert(InvoiceDesk.BadSignature.selector);
        _pay(_named("genuine"));
    }

    // ------------------------------------------------------------------ approvals are the payer's own

    function test_approvals_are_per_payer() public {
        Case memory c = _named("genuine_for_payer2");
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.UnknownVendor.selector, hostline));
        _pay(c); // payer2 never approved Hostline
        vm.prank(payer2);
        desk.approveVendor(hostline);
        _pay(c);
        assertTrue(desk.paid(payer2, c.id));
        assertFalse(desk.paid(payer, c.id), "paid is per payer too");
    }

    function test_removed_vendor_is_refused() public {
        vm.prank(payer);
        desk.removeVendor(hostline);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.UnknownVendor.selector, hostline));
        _pay(_named("genuine"));
    }

    function test_nobody_else_can_approve_for_a_payer() public {
        vm.prank(mallory);
        desk.approveVendor(mallory); // approves Mallory for MALLORY's own payments only
        assertFalse(desk.approved(payer, mallory));
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.UnknownVendor.selector, mallory));
        _pay(_named("mallory_own_invoice"));
    }

    // ------------------------------------------------------------------ transfer edge cases

    function test_vendor_that_rejects_payment_rolls_everything_back() public {
        vm.etch(hostline, type(RevertingVendor).runtimeCode);
        Case memory g = _named("genuine");
        uint256 before = payer.balance;
        vm.expectRevert(InvoiceDesk.TransferFailed.selector);
        _pay(g);
        assertFalse(desk.paid(payer, g.id));
        assertEq(payer.balance, before);
    }

    function test_reentrant_vendor_cannot_be_paid_twice() public {
        Case memory g = _named("genuine");
        vm.etch(hostline, type(ReentrantVendor).runtimeCode);
        ReentrantVendor(payable(hostline)).arm(desk, abi.encodeCall(InvoiceDesk.pay, (payable(g.vendor), g.amount, g.id, g.dueBy, g.signature)));
        _pay(g);
        assertTrue(ReentrantVendor(payable(hostline)).reentered());
        assertFalse(ReentrantVendor(payable(hostline)).reentrySucceeded());
        assertEq(hostline.balance, g.amount, "paid exactly once");
    }

    // ------------------------------------------------------------------ fuzz: every signed field is bound

    function testFuzz_any_other_amount_is_refused(uint256 amount) public {
        Case memory g = _named("genuine");
        vm.assume(amount != g.amount && amount < 50 ether);
        vm.prank(payer);
        vm.expectRevert(InvoiceDesk.BadSignature.selector);
        desk.pay{value: amount}(payable(g.vendor), amount, g.id, g.dueBy, g.signature);
    }

    function testFuzz_any_other_id_or_due_date_is_refused(bytes32 id, uint64 dueBy) public {
        Case memory g = _named("genuine");
        vm.assume(id != g.id || dueBy != g.dueBy);
        vm.assume(dueBy >= block.timestamp);
        vm.prank(payer);
        vm.expectRevert(InvoiceDesk.BadSignature.selector);
        desk.pay{value: g.amount}(payable(g.vendor), g.amount, id, dueBy, g.signature);
    }

    function testFuzz_only_the_payers_approved_vendors_get_past_the_first_check(address vendor) public {
        vm.assume(vendor != hostline && vendor != tokenwell);
        Case memory g = _named("genuine");
        vm.prank(payer);
        vm.expectRevert(abi.encodeWithSelector(InvoiceDesk.UnknownVendor.selector, vendor));
        desk.pay{value: g.amount}(payable(vendor), g.amount, g.id, g.dueBy, g.signature);
    }
}
