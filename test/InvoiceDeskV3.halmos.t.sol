// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

// Symbolic proofs for InvoiceDeskV3, run with Halmos (`halmos --contract InvoiceDeskV3Halmos`).
// Fuzzing tries many inputs; Halmos proves a property for EVERY input, by solving the contract's paths.
//
// The worst case for the limits: the PQC precompiles here say every vendor key is registered and every
// signature is valid. So these properties hold even for an attacker holding a perfectly valid ML-DSA-87
// signature. (That the signature check itself works is what the fixture tests, the invariants and the
// live chain show.)

import {Test} from "forge-std/Test.sol";
import {InvoiceDeskV3} from "../contracts/InvoiceDeskV3.sol";

contract VerifyAlwaysTrue { function pqcVerify(bytes calldata, bytes calldata, bytes calldata) external pure returns (bool) { return true; } }
contract StatusAlwaysProven { function pqcKeyStatus(address) external pure returns (bool, uint8, bytes memory, bool) { return (true, 1, hex"01", true); } }
contract PlainToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        require(allowance[f][msg.sender] >= a && balanceOf[f] >= a);
        allowance[f][msg.sender] -= a; balanceOf[f] -= a; balanceOf[to] += a; return true;
    }
}

contract InvoiceDeskV3Halmos is Test {
    InvoiceDeskV3 desk; PlainToken token;
    address constant PAYER = address(0x1000); address constant AGENT = address(0x2000); address constant VENDOR = address(0x3000);
    uint256 constant PER = 100e6; uint256 constant DAILY = 250e6;
    bytes constant SIG = hex"5151";

    function setUp() public {
        vm.etch(address(0x0a01), type(VerifyAlwaysTrue).runtimeCode);
        vm.etch(address(0x0a02), type(StatusAlwaysProven).runtimeCode);
        // plain CREATE: recent Foundry may compile `new` of another file's contract into a deployCode cheatcode
        bytes memory code = type(InvoiceDeskV3).creationCode;
        address d;
        assembly { d := create(0, add(code, 0x20), mload(code)) }
        desk = InvoiceDeskV3(d); token = new PlainToken();
        token.mint(PAYER, 1e30);
        vm.startPrank(PAYER);
        token.approve(address(desk), type(uint256).max);
        desk.approveVendor(VENDOR); desk.setAgent(AGENT, true); desk.setLimit(address(token), PER, DAILY);
        vm.stopPrank();
        vm.warp(1795000000);
    }

    function _pay(address from, address vendor, uint256 amount, bytes32 id, uint64 dueBy) internal returns (bool ok) {
        vm.prank(from);
        (ok,) = address(desk).call(abi.encodeCall(InvoiceDeskV3.pay, (PAYER, address(token), payable(vendor), amount, id, dueBy, SIG)));
    }

    /// Nobody but the payer and its named agent can make a payment, for any caller and any invoice.
    function check_strangers_never_pay(address caller, uint256 amount, bytes32 id, uint64 dueBy) public {
        vm.assume(caller != PAYER && caller != AGENT);
        assert(!_pay(caller, VENDOR, amount, id, dueBy));
    }

    /// A vendor the payer never approved is never paid, whoever sends it, whatever the invoice.
    function check_unapproved_vendor_never_paid(address vendor, bool asAgent, uint256 amount, bytes32 id, uint64 dueBy) public {
        vm.assume(vendor != VENDOR);
        assert(!_pay(asAgent ? AGENT : PAYER, vendor, amount, id, dueBy));
    }

    /// The agent never pays more than the per-payment limit, for any amount.
    function check_agent_per_payment_limit(uint256 amount, bytes32 id, uint64 dueBy) public {
        vm.assume(amount > PER);
        assert(!_pay(AGENT, VENDOR, amount, id, dueBy));
    }

    /// The agent never pays after the due date, for any time and any invoice; the payer may.
    function check_agent_never_pays_late(uint256 amount, bytes32 id, uint64 dueBy, uint32 late) public {
        vm.assume(late > 0 && amount > 0 && amount <= PER);
        vm.warp(uint256(dueBy) + late);
        assert(!_pay(AGENT, VENDOR, amount, id, dueBy));
        assert(_pay(PAYER, VENDOR, amount, id, dueBy));
    }

    /// Within one UTC day, two agent payments together never exceed the daily limit.
    function check_agent_daily_limit(uint256 a1, uint256 a2, bytes32 id1, bytes32 id2, uint32 gap) public {
        vm.assume(id1 != id2);
        uint64 due = uint64(block.timestamp + 365 days);
        bool ok1 = _pay(AGENT, VENDOR, a1, id1, due);
        vm.assume(block.timestamp / 1 days == (block.timestamp + gap) / 1 days); // still the same UTC day
        vm.warp(block.timestamp + gap);
        bool ok2 = _pay(AGENT, VENDOR, a2, id2, due);
        if (ok1 && ok2) assert(a1 + a2 <= DAILY);
    }

    /// An invoice (vendor, id) is paid at most once, whoever sends each attempt.
    function check_paid_at_most_once(bool first, bool second, uint256 amount, bytes32 id) public {
        uint64 due = uint64(block.timestamp + 365 days);
        bool ok1 = _pay(first ? AGENT : PAYER, VENDOR, amount, id, due);
        bool ok2 = _pay(second ? AGENT : PAYER, VENDOR, amount, id, due);
        assert(!(ok1 && ok2));
    }

    /// When a payment succeeds, the vendor receives exactly the invoiced amount, from the payer, and the desk keeps nothing.
    function check_exact_amount_moves(bool asAgent, uint256 amount, bytes32 id) public {
        uint256 pb = token.balanceOf(PAYER);
        uint256 vb = token.balanceOf(VENDOR);
        if (_pay(asAgent ? AGENT : PAYER, VENDOR, amount, id, uint64(block.timestamp + 1 days))) {
            assert(token.balanceOf(VENDOR) == vb + amount);
            assert(token.balanceOf(PAYER) == pb - amount);
            assert(token.balanceOf(address(desk)) == 0);
        }
    }

    /// No one but the payer can change the payer's settings: another account only writes its own entry.
    function check_settings_are_the_payers_alone(address caller, address who, uint256 per, uint256 day) public {
        vm.assume(caller != PAYER);
        vm.startPrank(caller);
        desk.setLimit(address(token), per, day); desk.setAgent(who, true); desk.approveVendor(who); desk.removeVendor(VENDOR);
        vm.stopPrank();
        (uint256 p, uint256 d) = desk.limits(PAYER, address(token));
        assert(p == PER && d == DAILY && desk.approved(PAYER, VENDOR));
        assert(who == AGENT || !desk.isAgent(PAYER, who));
    }
}
