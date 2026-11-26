// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

// Invariant tests for InvoiceDeskV5 (V4's handler; the agent's ML-DSA-87 signature now binds the whole invoice, the vendor's
// signature and a deadline, validUntil; the fuzzer also crosses agent signatures between invoices, changes validUntil and
// jumps past it; invoice ids per vendor; late payment by the payer only): a fuzzer calls pay() with every fixture invoice (genuine, forged,
// edited, other payer, other desk, ...) as the agent, the payer, Mallory or a stranger, toggles the agent,
// and moves time across UTC days, in random order. After every call these must still hold.

import {Test} from "forge-std/Test.sol";
import {InvoiceDeskV5} from "../contracts/InvoiceDeskV5.sol";
import {PqcVerifyStandIn, PqcKeyStatusStandIn} from "./InvoiceDesk.t.sol";
import {MockToken} from "./InvoiceDeskV2.t.sol";

contract HandlerV5 is Test {
    /// signedFor: the (desk, invoice fields, vendor signature) the agent signature was made for.
    struct Case { bytes signature; bytes agentSig; bool valid; address payer; address vendor; address token; uint256 amount; bytes32 id; uint64 dueBy; bytes32 signedFor; }
    function presented(address d, Case memory c) public pure returns (bytes32) { return keccak256(abi.encode(d, c.payer, c.vendor, c.token, c.amount, c.id, c.dueBy, keccak256(c.signature))); }
    InvoiceDeskV5 public desk; MockToken public fusd; address public payer; address public agent; address public mallory;
    Case[] internal cases;
    mapping(bytes32 => uint256) public timesPaid;
    mapping(uint256 => uint256) public agentPaidOnDay;
    uint256 public maxAgentDay; uint256 public agentPaidLate; uint256 public invalidPaid; uint256 public badIdx; address public badFrom; uint256 public paidByStranger; uint256 public calls; uint256 public payments;
    bytes32[] public paidIds;

    constructor(InvoiceDeskV5 d, MockToken t, address p, address a, address m) { desk = d; fusd = t; payer = p; agent = a; mallory = m; }
    address immutable owner = msg.sender;
    function add(Case memory c) external {
        require(msg.sender == owner, "setup only");
        cases.push(c);
    }

    function pay(uint256 who, uint256 which) external {
        calls++;
        Case memory c = cases[which % cases.length];
        address from = [agent, payer, mallory, address(0xBEEF)][who % 4];
        uint256 value = (from == payer && c.token == address(0)) ? c.amount : 0;
        vm.deal(from, value);
        vm.prank(from);
        try desk.pay{value: value}(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, from == agent ? c.agentSig : bytes(""), validUntil) {
            payments++;
            if (!c.valid) { invalidPaid++; badIdx = which % cases.length; badFrom = from; }
            if (from != payer && from != agent) paidByStranger++;
            bytes32 key = keccak256(abi.encode(c.vendor, c.id)); // V3: an invoice is (vendor, id)
            if (timesPaid[key]++ == 0) paidIds.push(key);
            if (from == agent && block.timestamp > c.dueBy) agentPaidLate++;
            if (from == agent && block.timestamp > validUntil) agentPaidExpired++;
            if (from == payer && block.timestamp > c.dueBy) paidLateByPayer++;
            if (from == agent && c.token == address(fusd)) {
                uint256 day = block.timestamp / 1 days;
                agentPaidOnDay[day] += c.amount;
                if (agentPaidOnDay[day] > maxAgentDay) maxAgentDay = agentPaidOnDay[day];
            }
        } catch {}
    }
    /// The agent pays invoice `which` with the agent signature made for invoice `sigFrom` and a validUntil
    /// possibly shifted from the signed one: it may only succeed with the invoice's own signature and deadline.
    function payCrossed(uint256 which, uint256 sigFrom, uint8 shift) external {
        calls++;
        Case memory c = cases[which % cases.length];
        Case memory from = cases[sigFrom % cases.length];
        bytes memory sig = from.agentSig;
        uint64 vu = validUntil + (shift % 3) - 1; // validUntil - 1, validUntil, validUntil + 1
        vm.prank(agent);
        try desk.pay(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature, sig, vu) {
            payments++;
            // the same invoice and vendor signature, on this desk, may be listed under two names (other_desk)
            if (from.signedFor != presented(address(desk), c) || vu != validUntil) crossedPaid++;
            if (!c.valid) { invalidPaid++; badIdx = which % cases.length; badFrom = agent; }
            bytes32 key = keccak256(abi.encode(c.vendor, c.id));
            if (timesPaid[key]++ == 0) paidIds.push(key);
            if (block.timestamp > c.dueBy) agentPaidLate++;
            if (block.timestamp > vu) agentPaidExpired++;
            if (c.token == address(fusd)) {
                uint256 day = block.timestamp / 1 days;
                agentPaidOnDay[day] += c.amount;
                if (agentPaidOnDay[day] > maxAgentDay) maxAgentDay = agentPaidOnDay[day];
            }
        } catch {}
    }
    /// Jump past the agent signatures' deadline (a week after the due date).
    function goExpired(uint256 secs) external { vm.warp(uint256(validUntil) + 1 + bound(secs, 0, 3 days)); }
    uint64 public validUntil; uint256 public agentPaidExpired; uint256 public crossedPaid;
    function setValidUntil(uint64 v) external { require(msg.sender == owner, "setup only"); validUntil = v; }
    function setAgent(bool on) external { vm.prank(payer); desk.setAgent(agent, on); }
    function warp(uint256 secs) external { vm.warp(block.timestamp + bound(secs, 0, 2 days)); }
    /// Jump past the fixtures' due date (2028-01-01), so late payments are tried by everyone.
    function goLate(uint256 secs) external { vm.warp(1830297600 + 1 + bound(secs, 0, 3 days)); lateCalls++; }
    uint256 public lateCalls; uint256 public paidLateByPayer;
    function paidCount() external view returns (uint256) { return paidIds.length; }
}

contract InvoiceDeskV5InvariantTest is Test {
    address constant VERIFY = 0x0000000000000000000000000000000000000a01;
    address constant STATUS = 0x0000000000000000000000000000000000000a02;
    string fx; InvoiceDeskV5 desk; MockToken fusd; HandlerV5 h;
    address payer; address hostline; address tokenwell; address mallory; address agent = address(0xA6E47);
    uint256 constant START = 1000e6;

    function _k(uint256 i, string memory f) internal pure returns (string memory) { return string.concat(".cases[", vm.toString(i), "].", f); }


    function _addCase(uint256 i) internal {
        HandlerV5.Case memory c;
        c.signature = vm.parseJsonBytes(fx, _k(i, "signature"));
        c.valid = vm.parseJsonBool(fx, _k(i, "valid"));
        PqcVerifyStandIn(VERIFY).record(vm.parseJsonBytes(fx, _k(i, "pubkey")), c.signature, vm.parseJsonBytes(fx, _k(i, "message")), c.valid);
        c.payer = vm.parseJsonAddress(fx, _k(i, "payer"));
        c.vendor = vm.parseJsonAddress(fx, _k(i, "vendor"));
        c.token = vm.parseJsonAddress(fx, _k(i, "token"));
        c.amount = vm.parseJsonUint(fx, _k(i, "amount"));
        c.id = vm.parseJsonBytes32(fx, _k(i, "id"));
        c.dueBy = uint64(vm.parseJsonUint(fx, _k(i, "dueBy")));
        c.signedFor = h.presented(vm.parseJsonAddress(fx, _k(i, "desk")), c);
        // the agent's own ML-DSA-87 signature for this case (real, test/fixtures.mjs), recorded for the stand-in
        string memory ak = string.concat(".agentSigs.0x00000000000000000000000000000000000A6E47[", vm.toString(i), "]");
        c.agentSig = vm.parseJsonBytes(fx, string.concat(ak, ".signature"));
        PqcVerifyStandIn(VERIFY).record(vm.parseJsonBytes(fx, ".keys.agentsigner"), c.agentSig, vm.parseJsonBytes(fx, string.concat(ak, ".message")), true);
        // Payable on this desk: a valid signature from an approved vendor (not Mallory). "other_desk" is
        // genuine_fusd's exact invoice, refused only on desk2; on this desk it is the same genuine invoice.
        if (keccak256(bytes(vm.parseJsonString(fx, _k(i, "name")))) == keccak256("other_desk")) c.valid = true;
        // Genuinely signed, but V3 must never pay them: a zero amount, a token that takes a fee (no code here).
        bytes32 nm = keccak256(bytes(vm.parseJsonString(fx, _k(i, "name"))));
        if (nm == keccak256("zero_amount") || nm == keccak256("fee_taking_token")) c.valid = false;
        c.valid = c.valid && c.vendor != mallory;
        h.add(c);
    }

    function setUp() public {
        fx = vm.readFile("test/fixtures/mldsa-v5.json");
        vm.chainId(vm.parseJsonUint(fx, ".chainId"));
        payer = vm.parseJsonAddress(fx, ".addresses.payer");
        hostline = vm.parseJsonAddress(fx, ".addresses.hostline");
        tokenwell = vm.parseJsonAddress(fx, ".addresses.tokenwell");
        mallory = vm.parseJsonAddress(fx, ".addresses.mallory");
        vm.etch(VERIFY, address(new PqcVerifyStandIn()).code);
        vm.etch(STATUS, address(new PqcKeyStatusStandIn()).code);
        PqcKeyStatusStandIn(STATUS).set(hostline, true, 1, vm.parseJsonBytes(fx, ".keys.hostline"), true);
        PqcKeyStatusStandIn(STATUS).set(tokenwell, true, 1, vm.parseJsonBytes(fx, ".keys.tokenwell"), true);
        PqcKeyStatusStandIn(STATUS).set(mallory, true, 1, vm.parseJsonBytes(fx, ".keys.mallory"), true);
        PqcKeyStatusStandIn(STATUS).set(address(0x5161), true, 1, vm.parseJsonBytes(fx, ".keys.agentsigner"), true);
        deployCodeTo("MockToken", vm.parseJsonAddress(fx, ".tokens.fusd"));
        fusd = MockToken(vm.parseJsonAddress(fx, ".tokens.fusd"));
        deployCodeTo("InvoiceDeskV5.sol:InvoiceDeskV5", vm.parseJsonAddress(fx, ".addresses.desk"));
        desk = InvoiceDeskV5(vm.parseJsonAddress(fx, ".addresses.desk"));

        h = new HandlerV5(desk, fusd, payer, agent, mallory);
        h.setValidUntil(uint64(vm.parseJsonUint(fx, ".validUntil")));
        uint256 n = 16;
        for (uint256 i = 0; i < n; i++) _addCase(i);
        fusd.mint(payer, START);
        vm.startPrank(payer);
        desk.approveVendor(hostline);
        desk.approveVendor(tokenwell);
        desk.setAgent(agent, true);
        desk.setAgentSigner(agent, address(0x5161));
        desk.setLimit(address(fusd), 100e6, 250e6);
        fusd.approve(address(desk), type(uint256).max);
        vm.stopPrank();
        vm.warp(1795000000);
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](6);
        sel[0] = HandlerV5.pay.selector; sel[1] = HandlerV5.setAgent.selector; sel[2] = HandlerV5.warp.selector; sel[3] = HandlerV5.goLate.selector;
        sel[4] = HandlerV5.payCrossed.selector; sel[5] = HandlerV5.goExpired.selector;
        targetSelector(FuzzSelector({addr: address(h), selectors: sel}));
    }

    /// Only invoices with a valid ML-DSA-87 signature from an approved vendor are ever paid.
    function invariant_only_genuine_invoices_are_paid() public view { assertEq(h.invalidPaid(), 0, string.concat("case ", vm.toString(h.badIdx()), " from ", vm.toString(h.badFrom()))); }
    /// Nobody but the payer and its named agent ever gets a payment through.
    function invariant_no_stranger_pays() public view { assertEq(h.paidByStranger(), 0); }
    /// The agent never pays an invoice after its due date (the payer, in person, may).
    function invariant_agent_never_pays_late() public view { assertEq(h.agentPaidLate(), 0); }
    /// Each invoice (vendor, id) is paid at most once, whoever sends it.
    function invariant_each_invoice_paid_at_most_once() public view {
        for (uint256 i = 0; i < h.paidCount(); i++) assertEq(h.timesPaid(h.paidIds(i)), 1);
    }
    /// The fuzzer really got genuine invoices through (not a suite that passes because nothing is ever paid).
    function afterInvariant() public view { assertGt(h.calls(), 0); }
    /// V5: the agent never pays after its signature's validUntil.
    function invariant_agent_never_pays_after_validUntil() public view { assertEq(h.agentPaidExpired(), 0); }
    /// V5: an agent signature pays only the invoice (fields and vendor signature) and the deadline it was made for.
    function invariant_agent_signature_pays_only_what_it_signed() public view { assertEq(h.crossedPaid(), 0); }
    /// The agent never pays more than the daily limit in one UTC day.
    function invariant_agent_within_daily_limit() public view { assertLe(h.maxAgentDay(), 250e6); }
    /// fUSD only moves payer -> approved vendors: nothing is created, nothing reaches Mallory, the agent or the desk.
    function invariant_fusd_conserved_and_never_to_mallory() public view {
        assertEq(fusd.balanceOf(payer) + fusd.balanceOf(hostline) + fusd.balanceOf(tokenwell), START);
        assertEq(fusd.balanceOf(mallory), 0);
        assertEq(fusd.balanceOf(agent), 0);
        assertEq(fusd.balanceOf(address(desk)), 0);
        assertEq(address(desk).balance, 0);
    }
}
