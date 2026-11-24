// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// QoreChain post-quantum precompiles (diana testnet).
interface IQorePQCv3 {
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external view returns (bool valid);
    function pqcKeyStatus(address account)
        external view returns (bool registered, uint8 algorithmId, bytes memory pubkey, bool possessionProven);
}

/// @title InvoiceDeskV3
/// @notice Pays a payer's ML-DSA-87 signed invoices, in an ERC-20 such as fUSD (or QOR when the payer
/// pays in person), on behalf of an AI agent that holds no money of its own.
///
/// V3 keeps V2's design and its signed invoice format (vendors' signatures and tools are unchanged) and
/// fixes what a real accounts-payable team runs into:
///   - Invoice numbers are per vendor: paid[payer][vendor][id]. Two vendors may both use "INV-001".
///     (V2 keyed paid[payer][id], so the second vendor's invoice came back AlreadyPaid.)
///   - A late invoice can still be settled, by the payer in person. Agents stay bound by the due date.
///   - A zero-amount invoice is refused (it would only burn an invoice number).
///   - For an ERC-20, the desk checks that the vendor's balance rose by exactly the invoiced amount, so a
///     token that takes a fee or misreports a transfer is refused, not "paid".
///
/// What `pay` checks, in order:
///   1. the caller is the payer, or an agent the payer named           NotPayersAgent
///   2. the vendor is on the payer's approved list                     UnknownVendor
///   3. the vendor's ML-DSA-87 key is registered, proven, current      VendorKeyNotProven
///   4. that key signed exactly these bytes (payer, vendor, currency,
///      amount, invoice id, due date, this desk, this chain)           BadSignature
///   5. a non-zero amount, not paid before (this vendor, this id)      ZeroAmount, AlreadyPaid
///   6. for an agent: not past due, ERC-20 only, within the payer's
///      per-payment and daily limit for that token (UTC day)           PastDue, AgentCannotPayNative,
///                                                                     OverPerPaymentLimit, OverDailyLimit
///   7. exactly the invoiced amount reaches the vendor, in one call    WrongAmount, TransferFailed
contract InvoiceDeskV3 {
    IQorePQCv3 constant PQC_VERIFY = IQorePQCv3(0x0000000000000000000000000000000000000a01);
    IQorePQCv3 constant PQC_STATUS = IQorePQCv3(0x0000000000000000000000000000000000000a02);
    uint8 constant ALG_ML_DSA_87 = 1;
    /// The signed invoice format is V2's, unchanged: the desk address and chain id in it already bind
    /// every signature to one desk.
    bytes32 constant DOMAIN = keccak256("LEASH-INVOICE-v2");

    struct Limit { uint256 perPayment; uint256 daily; }

    /// payer => vendor => approved
    mapping(address => mapping(address => bool)) public approved;
    /// payer => vendor => invoice id => paid
    mapping(address => mapping(address => mapping(bytes32 => bool))) public paid;
    /// payer => agent account => may pay for this payer
    mapping(address => mapping(address => bool)) public isAgent;
    /// payer => token => what its agents may pay (0/0 = nothing)
    mapping(address => mapping(address => Limit)) public limits;
    /// payer => token => UTC day => paid by its agents that day
    mapping(address => mapping(address => mapping(uint256 => uint256))) public spentByAgents;

    event VendorApproved(address indexed payer, address indexed vendor, bool approved);
    event AgentSet(address indexed payer, address indexed agent, bool active);
    event LimitSet(address indexed payer, address indexed token, uint256 perPayment, uint256 daily);
    event InvoicePaid(address indexed payer, address indexed vendor, bytes32 indexed id, address token, uint256 amount, address by);

    error NotPayersAgent(address caller);
    error UnknownVendor(address vendor);
    error VendorKeyNotProven(address vendor);
    error BadSignature();
    error ZeroAmount();
    error AlreadyPaid(bytes32 id);
    error PastDue(uint64 dueBy);
    error AgentCannotPayNative();
    error OverPerPaymentLimit(uint256 amount, uint256 limit);
    error OverDailyLimit(uint256 spentToday, uint256 amount, uint256 limit);
    error WrongAmount(uint256 sent, uint256 invoiced);
    error TransferFailed();

    // ------------------------------------------------------------ the payer's settings (msg.sender = payer)

    function approveVendor(address vendor) external { approved[msg.sender][vendor] = true; emit VendorApproved(msg.sender, vendor, true); }
    function removeVendor(address vendor) external { approved[msg.sender][vendor] = false; emit VendorApproved(msg.sender, vendor, false); }
    /// Name (or remove) an agent account that may pay this payer's invoices. Removing is a kill switch.
    function setAgent(address agent, bool active) external { isAgent[msg.sender][agent] = active; emit AgentSet(msg.sender, agent, active); }
    function setLimit(address token, uint256 perPayment, uint256 daily) external {
        limits[msg.sender][token] = Limit(perPayment, daily);
        emit LimitSet(msg.sender, token, perPayment, daily);
    }

    // ------------------------------------------------------------ invoices

    /// The exact bytes a vendor signs. Readable by anyone so off-chain tools sign the same thing.
    function invoiceMessage(address payer, address vendor, address token, uint256 amount, bytes32 id, uint64 dueBy)
        public view returns (bytes memory)
    {
        return abi.encode(DOMAIN, block.chainid, address(this), payer, vendor, token, amount, id, dueBy);
    }

    /// How much more the payer's agents may pay in `token` today.
    function remainingToday(address payer, address token) external view returns (uint256) {
        uint256 s = spentByAgents[payer][token][block.timestamp / 1 days];
        uint256 d = limits[payer][token].daily;
        return s >= d ? 0 : d - s;
    }

    /// @param token address(0) for native QOR (payer in person only, sent as msg.value), else the ERC-20.
    function pay(address payer, address token, address payable vendor, uint256 amount, bytes32 id, uint64 dueBy, bytes calldata signature)
        external payable
    {
        bool byAgent = msg.sender != payer;
        if (byAgent && !isAgent[payer][msg.sender]) revert NotPayersAgent(msg.sender);
        if (!approved[payer][vendor]) revert UnknownVendor(vendor);
        if (!PQC_VERIFY.pqcVerify(_vendorKey(vendor), signature, invoiceMessage(payer, vendor, token, amount, id, dueBy))) {
            revert BadSignature();
        }
        if (amount == 0) revert ZeroAmount();
        if (paid[payer][vendor][id]) revert AlreadyPaid(id);
        if (byAgent) {
            if (block.timestamp > dueBy) revert PastDue(dueBy);
            _agentLimits(payer, token, amount);
        }
        uint256 native = token == address(0) ? amount : 0;
        if (msg.value != native) revert WrongAmount(msg.value, native);

        paid[payer][vendor][id] = true;
        emit InvoicePaid(payer, vendor, id, token, amount, msg.sender);
        if (token == address(0)) {
            (bool ok,) = vendor.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            // transferFrom(payer, vendor, amount) against the allowance the payer gave this desk.
            // A call to an address without code would "succeed" and move nothing: refused first.
            if (token.code.length == 0) revert TransferFailed();
            uint256 before = _balanceOf(token, vendor);
            (bool ok, bytes memory ret) = token.call(abi.encodeWithSelector(0x23b872dd, payer, vendor, amount));
            if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed();
            if (_balanceOf(token, vendor) != before + amount) revert TransferFailed();
        }
    }

    function _balanceOf(address token, address who) internal view returns (uint256) {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(0x70a08231, who));
        if (!ok || ret.length < 32) revert TransferFailed();
        return abi.decode(ret, (uint256));
    }

    function _agentLimits(address payer, address token, uint256 amount) internal {
        if (token == address(0)) revert AgentCannotPayNative();
        Limit memory l = limits[payer][token];
        if (amount > l.perPayment) revert OverPerPaymentLimit(amount, l.perPayment);
        uint256 day = block.timestamp / 1 days;
        uint256 s = spentByAgents[payer][token][day];
        if (s + amount > l.daily) revert OverDailyLimit(s, amount, l.daily);
        spentByAgents[payer][token][day] = s + amount;
    }

    /// The vendor's ML-DSA-87 public key, read from the chain's PQC module at payment time.
    function _vendorKey(address vendor) internal view returns (bytes memory pubkey) {
        bool registered;
        uint8 alg;
        bool proven;
        (registered, alg, pubkey, proven) = PQC_STATUS.pqcKeyStatus(vendor);
        if (!registered || !proven || alg != ALG_ML_DSA_87) revert VendorKeyNotProven(vendor);
    }
}
