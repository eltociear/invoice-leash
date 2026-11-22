// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// QoreChain post-quantum precompiles (diana testnet).
interface IQorePQCv2 {
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external view returns (bool valid);
    function pqcKeyStatus(address account)
        external view returns (bool registered, uint8 algorithmId, bytes memory pubkey, bool possessionProven);
}

/// @title InvoiceDeskV2
/// @notice Pays a payer's ML-DSA-87 signed invoices, in an ERC-20 such as fUSD (or QOR when the payer
/// pays in person), on behalf of an AI agent that holds no money of its own.
///
/// Why v2 is shaped this way (measured on qorechain-diana, see runs/probes/):
///   A key bound by a QoreChain spending rule can always move value in the denoms its rule allows:
///   plain value transfers for QOR, and transfer/approve for every ERC-20 listed in allowed_denoms,
///   whatever allowed_evm_calls says. And the chain refuses an ERC-20 outflow from the account in a
///   denom the rule does not list, even through an allowed call. So an agent that acts AS the
///   payer's account can either pay nothing in fUSD, or send fUSD anywhere within its limits.
///
///   v2 therefore gives the agent its OWN account, which holds nothing and whose rule allows no
///   denom at all and exactly one call: this contract's `pay`. The money stays in the payer's
///   account (no vault); the payer gives this desk an ERC-20 allowance (the budget), names its
///   agents, and sets per-payment and daily limits per token here. Only the payer can change any of
///   that: the agent is a different account, so msg.sender tells them apart (in v1 it could not).
///
/// What `pay` checks, in order:
///   1. the caller is the payer, or an agent the payer named           NotPayersAgent
///   2. the vendor is on the payer's approved list                     UnknownVendor
///   3. the vendor's ML-DSA-87 key is registered, proven, current      VendorKeyNotProven
///   4. that key signed exactly these bytes (payer, vendor, currency,
///      amount, invoice id, due date, this desk, this chain)           BadSignature
///   5. not paid before, not past due                                  AlreadyPaid, PastDue
///   6. for an agent: ERC-20 only, within the payer's per-payment and
///      daily limit for that token (UTC day)                           AgentCannotPayNative, OverPerPaymentLimit, OverDailyLimit
///   7. the right amount moves, payer -> vendor, in one call           WrongAmount, TransferFailed
contract InvoiceDeskV2 {
    IQorePQCv2 constant PQC_VERIFY = IQorePQCv2(0x0000000000000000000000000000000000000a01);
    IQorePQCv2 constant PQC_STATUS = IQorePQCv2(0x0000000000000000000000000000000000000a02);
    uint8 constant ALG_ML_DSA_87 = 1;
    bytes32 constant DOMAIN = keccak256("LEASH-INVOICE-v2");

    struct Limit { uint256 perPayment; uint256 daily; }

    /// payer => vendor => approved
    mapping(address => mapping(address => bool)) public approved;
    /// payer => invoice id => paid
    mapping(address => mapping(bytes32 => bool)) public paid;
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
        if (paid[payer][id]) revert AlreadyPaid(id);
        if (block.timestamp > dueBy) revert PastDue(dueBy);
        if (byAgent) _agentLimits(payer, token, amount);
        uint256 native = token == address(0) ? amount : 0;
        if (msg.value != native) revert WrongAmount(msg.value, native);

        paid[payer][id] = true;
        emit InvoicePaid(payer, vendor, id, token, amount, msg.sender);
        if (token == address(0)) {
            (bool ok,) = vendor.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            // transferFrom(payer, vendor, amount) against the allowance the payer gave this desk.
            // A call to an address without code would "succeed" and move nothing: refused first.
            if (token.code.length == 0) revert TransferFailed();
            (bool ok, bytes memory ret) = token.call(abi.encodeWithSelector(0x23b872dd, payer, vendor, amount));
            if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed();
        }
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
