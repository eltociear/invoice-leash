// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// QoreChain post-quantum precompiles (diana testnet).
interface IQorePQCv4 {
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external view returns (bool valid);
    function pqcKeyStatus(address account)
        external view returns (bool registered, uint8 algorithmId, bytes memory pubkey, bool possessionProven);
}

/// @title InvoiceDeskV4
/// @notice InvoiceDeskV3, plus a post-quantum signature from the agent itself.
///
/// On QoreChain today an agent's linked key is ed25519 or secp256k1: a quantum computer could derive it
/// from its public key on chain. In V3 that key alone could pay genuine invoices within the limits. In V4
/// an agent's payment also needs the agent's own ML-DSA-87 signature over this desk, this payer, this
/// agent and this exact invoice, checked by the PQC precompile against the key of the signer account the
/// payer named for that agent (setAgentSigner). The payer paying in person needs no agent signature.
/// Everything else is V3's: the vendor's ML-DSA-87 invoice signature, invoice ids per vendor, limits,
/// late settlement by the payer only, zero amounts refused, the vendor's receipt checked.
///
/// What `pay` checks, in order:
///   1. the caller is the payer, or an agent the payer named           NotPayersAgent
///   2. for an agent: the payer named its ML-DSA-87 signer, whose key
///      is registered and proven, and it signed this payment           AgentSignerNotSet, AgentKeyNotProven,
///                                                                     BadAgentSignature
///   3. the vendor is on the payer's approved list                     UnknownVendor
///   4. the vendor's ML-DSA-87 key is registered, proven, current      VendorKeyNotProven
///   5. that key signed exactly these bytes                            BadSignature
///   6. a non-zero amount, not paid before (this vendor, this id)      ZeroAmount, AlreadyPaid
///   7. for an agent: not past due, ERC-20 only, within the limits      PastDue, AgentCannotPayNative,
///                                                                     OverPerPaymentLimit, OverDailyLimit
///   8. exactly the invoiced amount reaches the vendor, in one call    WrongAmount, TransferFailed
contract InvoiceDeskV4 {
    IQorePQCv4 constant PQC_VERIFY = IQorePQCv4(0x0000000000000000000000000000000000000a01);
    IQorePQCv4 constant PQC_STATUS = IQorePQCv4(0x0000000000000000000000000000000000000a02);
    uint8 constant ALG_ML_DSA_87 = 1;
    /// The signed invoice format is V2's, unchanged: the desk address and chain id in it already bind
    /// every signature to one desk.
    bytes32 constant DOMAIN = keccak256("LEASH-INVOICE-v2");
    /// What an agent signs: a different domain, so an invoice signature can never pass as an agent's.
    bytes32 constant AGENT_DOMAIN = keccak256("LEASH-AGENT-PAY-v1");

    struct Limit { uint256 perPayment; uint256 daily; }

    /// payer => vendor => approved
    mapping(address => mapping(address => bool)) public approved;
    /// payer => vendor => invoice id => paid
    mapping(address => mapping(address => mapping(bytes32 => bool))) public paid;
    /// payer => agent account => may pay for this payer
    mapping(address => mapping(address => bool)) public isAgent;
    /// payer => agent account => the account whose registered ML-DSA-87 key must sign the agent's payments
    mapping(address => mapping(address => address)) public agentSigner;
    /// payer => token => what its agents may pay (0/0 = nothing)
    mapping(address => mapping(address => Limit)) public limits;
    /// payer => token => UTC day => paid by its agents that day
    mapping(address => mapping(address => mapping(uint256 => uint256))) public spentByAgents;

    event VendorApproved(address indexed payer, address indexed vendor, bool approved);
    event AgentSet(address indexed payer, address indexed agent, bool active);
    event AgentSignerSet(address indexed payer, address indexed agent, address signer);
    event LimitSet(address indexed payer, address indexed token, uint256 perPayment, uint256 daily);
    event InvoicePaid(address indexed payer, address indexed vendor, bytes32 indexed id, address token, uint256 amount, address by);

    error NotPayersAgent(address caller);
    error AgentSignerNotSet(address agent);
    error AgentKeyNotProven(address signer);
    error BadAgentSignature();
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
    /// Name the account whose ML-DSA-87 key must sign this agent's payments (address(0) blocks the agent).
    function setAgentSigner(address agent, address signer) external { agentSigner[msg.sender][agent] = signer; emit AgentSignerSet(msg.sender, agent, signer); }
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

    /// The exact bytes an agent's ML-DSA-87 signer signs for one payment.
    function agentMessage(address payer, address agent, address token, address vendor, uint256 amount, bytes32 id)
        public view returns (bytes memory)
    {
        return abi.encode(AGENT_DOMAIN, block.chainid, address(this), payer, agent, vendor, token, amount, id);
    }

    /// How much more the payer's agents may pay in `token` today.
    function remainingToday(address payer, address token) external view returns (uint256) {
        uint256 s = spentByAgents[payer][token][block.timestamp / 1 days];
        uint256 d = limits[payer][token].daily;
        return s >= d ? 0 : d - s;
    }

    /// @param token address(0) for native QOR (payer in person only, sent as msg.value), else the ERC-20.
    /// @param agentSignature the agent signer's ML-DSA-87 signature over agentMessage(...); empty when the payer pays.
    function pay(address payer, address token, address payable vendor, uint256 amount, bytes32 id, uint64 dueBy, bytes calldata signature, bytes calldata agentSignature)
        external payable
    {
        bool byAgent = msg.sender != payer;
        if (byAgent && !isAgent[payer][msg.sender]) revert NotPayersAgent(msg.sender);
        if (byAgent) _agentSignature(payer, token, vendor, amount, id, agentSignature);
        _vendorSignature(payer, token, vendor, amount, id, dueBy, signature);
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
        _transfer(payer, token, vendor, amount);
    }

    /// Moves exactly `amount` from the payer to the vendor: QOR sent with the call, or the ERC-20 pulled
    /// against the allowance, with the vendor's balance checked before and after.
    function _transfer(address payer, address token, address payable vendor, uint256 amount) internal {
        if (token == address(0)) {
            (bool sent,) = vendor.call{value: amount}("");
            if (!sent) revert TransferFailed();
            return;
        }
        // A call to an address without code would "succeed" and move nothing: refused first.
        if (token.code.length == 0) revert TransferFailed();
        uint256 before = _balanceOf(token, vendor);
        (bool ok, bytes memory ret) = token.call(abi.encodeWithSelector(0x23b872dd, payer, vendor, amount));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed();
        if (_balanceOf(token, vendor) != before + amount) revert TransferFailed();
    }

    function _vendorSignature(address payer, address token, address vendor, uint256 amount, bytes32 id, uint64 dueBy, bytes calldata signature) internal view {
        if (!approved[payer][vendor]) revert UnknownVendor(vendor);
        if (!PQC_VERIFY.pqcVerify(_vendorKey(vendor), signature, invoiceMessage(payer, vendor, token, amount, id, dueBy))) revert BadSignature();
    }

    function _agentSignature(address payer, address token, address vendor, uint256 amount, bytes32 id, bytes calldata agentSignature) internal view {
        bytes memory message = agentMessage(payer, msg.sender, token, vendor, amount, id);
        if (!PQC_VERIFY.pqcVerify(_agentKey(payer), agentSignature, message)) revert BadAgentSignature();
    }

    /// The ML-DSA-87 key of the signer the payer named for this agent, read from the chain at payment time.
    function _agentKey(address payer) internal view returns (bytes memory pubkey) {
        address signer = agentSigner[payer][msg.sender];
        if (signer == address(0)) revert AgentSignerNotSet(msg.sender);
        bool registered;
        uint8 alg;
        bool proven;
        (registered, alg, pubkey, proven) = PQC_STATUS.pqcKeyStatus(signer);
        if (!registered || !proven || alg != ALG_ML_DSA_87) revert AgentKeyNotProven(signer);
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
