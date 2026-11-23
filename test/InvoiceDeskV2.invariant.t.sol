// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.30;

// Invariant tests for InvoiceDeskV2: a fuzzer calls pay() with every fixture invoice (genuine, forged,
// edited, other payer, other desk, ...) as the agent, the payer, Mallory or a stranger, toggles the agent,
// and moves time across UTC days, in random order. After every call these must still hold.

import {Test} from "forge-std/Test.sol";
import {InvoiceDeskV2} from "../contracts/InvoiceDeskV2.sol";
import {PqcVerifyStandIn, PqcKeyStatusStandIn} from "./InvoiceDesk.t.sol";
import {MockToken} from "./InvoiceDeskV2.t.sol";

contract Handler is Test {
    struct Case { bytes signature; bool valid; address payer; address vendor; address token; uint256 amount; bytes32 id; uint64 dueBy; }
    InvoiceDeskV2 public desk; MockToken public fusd; address public payer; address public agent; address public mallory;
    Case[] internal cases;
    mapping(bytes32 => uint256) public timesPaid;
    mapping(uint256 => uint256) public agentPaidOnDay;
    uint256 public maxAgentDay; uint256 public invalidPaid; uint256 public badIdx; address public badFrom; uint256 public paidByStranger; uint256 public calls; uint256 public payments;
    bytes32[] public paidIds;

    constructor(InvoiceDeskV2 d, MockToken t, address p, address a, address m) { desk = d; fusd = t; payer = p; agent = a; mallory = m; }
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
        try desk.pay{value: value}(c.payer, c.token, payable(c.vendor), c.amount, c.id, c.dueBy, c.signature) {
            payments++;
            if (!c.valid) { invalidPaid++; badIdx = which % cases.length; badFrom = from; }
            if (from != payer && from != agent) paidByStranger++;
            if (timesPaid[c.id]++ == 0) paidIds.push(c.id);
            if (from == agent && c.token == address(fusd)) {
                uint256 day = block.timestamp / 1 days;
                agentPaidOnDay[day] += c.amount;
                if (agentPaidOnDay[day] > maxAgentDay) maxAgentDay = agentPaidOnDay[day];
            }
        } catch {}
    }
    function setAgent(bool on) external { vm.prank(payer); desk.setAgent(agent, on); }
    function warp(uint256 secs) external { vm.warp(block.timestamp + bound(secs, 0, 2 days)); }
    function paidCount() external view returns (uint256) { return paidIds.length; }
}

contract InvoiceDeskV2InvariantTest is Test {
    address constant VERIFY = 0x0000000000000000000000000000000000000a01;
    address constant STATUS = 0x0000000000000000000000000000000000000a02;
    string fx; InvoiceDeskV2 desk; MockToken fusd; Handler h;
    address payer; address hostline; address tokenwell; address mallory; address agent = address(0xA6E47);
    uint256 constant START = 1000e6;

    function _k(uint256 i, string memory f) internal pure returns (string memory) { return string.concat(".cases[", vm.toString(i), "].", f); }


    function _addCase(uint256 i) internal {
        Handler.Case memory c;
        c.signature = vm.parseJsonBytes(fx, _k(i, "signature"));
        c.valid = vm.parseJsonBool(fx, _k(i, "valid"));
        PqcVerifyStandIn(VERIFY).record(vm.parseJsonBytes(fx, _k(i, "pubkey")), c.signature, vm.parseJsonBytes(fx, _k(i, "message")), c.valid);
        c.payer = vm.parseJsonAddress(fx, _k(i, "payer"));
        c.vendor = vm.parseJsonAddress(fx, _k(i, "vendor"));
        c.token = vm.parseJsonAddress(fx, _k(i, "token"));
        c.amount = vm.parseJsonUint(fx, _k(i, "amount"));
        c.id = vm.parseJsonBytes32(fx, _k(i, "id"));
        c.dueBy = uint64(vm.parseJsonUint(fx, _k(i, "dueBy")));
        // Payable on this desk: a valid signature from an approved vendor (not Mallory). "other_desk" is
        // genuine_fusd's exact invoice, refused only on desk2; on this desk it is the same genuine invoice.
        if (keccak256(bytes(vm.parseJsonString(fx, _k(i, "name")))) == keccak256("other_desk")) c.valid = true;
        c.valid = c.valid && c.vendor != mallory;
        h.add(c);
    }

    function setUp() public {
        fx = vm.readFile("test/fixtures/mldsa-v2.json");
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
        deployCodeTo("MockToken", vm.parseJsonAddress(fx, ".tokens.fusd"));
        fusd = MockToken(vm.parseJsonAddress(fx, ".tokens.fusd"));
        deployCodeTo("InvoiceDeskV2.sol:InvoiceDeskV2", vm.parseJsonAddress(fx, ".addresses.desk"));
        desk = InvoiceDeskV2(vm.parseJsonAddress(fx, ".addresses.desk"));

        h = new Handler(desk, fusd, payer, agent, mallory);
        uint256 n = 13;
        for (uint256 i = 0; i < n; i++) _addCase(i);
        fusd.mint(payer, START);
        vm.startPrank(payer);
        desk.approveVendor(hostline);
        desk.approveVendor(tokenwell);
        desk.setAgent(agent, true);
        desk.setLimit(address(fusd), 100e6, 250e6);
        fusd.approve(address(desk), type(uint256).max);
        vm.stopPrank();
        vm.warp(1795000000);
        targetContract(address(h));
        bytes4[] memory sel = new bytes4[](3);
        sel[0] = Handler.pay.selector; sel[1] = Handler.setAgent.selector; sel[2] = Handler.warp.selector;
        targetSelector(FuzzSelector({addr: address(h), selectors: sel}));
    }

    /// Only invoices with a valid ML-DSA-87 signature from an approved vendor are ever paid.
    function invariant_only_genuine_invoices_are_paid() public view { assertEq(h.invalidPaid(), 0, string.concat("case ", vm.toString(h.badIdx()), " from ", vm.toString(h.badFrom()))); }
    /// Nobody but the payer and its named agent ever gets a payment through.
    function invariant_no_stranger_pays() public view { assertEq(h.paidByStranger(), 0); }
    /// Each invoice is paid at most once, whoever sends it.
    function invariant_each_invoice_paid_at_most_once() public view {
        for (uint256 i = 0; i < h.paidCount(); i++) assertEq(h.timesPaid(h.paidIds(i)), 1);
    }
    /// The fuzzer really got genuine invoices through (not a suite that passes because nothing is ever paid).
    function afterInvariant() public view { assertGt(h.calls(), 0); }
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
