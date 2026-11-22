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
/// @notice Pays an invoice, in QOR or in an ERC-20 such as fUSD, only when it is signed with
/// ML-DSA-87 by a vendor the payer approved.
///
/// Same design as v1 (see InvoiceDesk.sol): the agent acts AS the payer's account, so its chain
/// rule scopes it to `pay` alone, and the value limits live in that rule, not here. What v2 adds:
///   - the currency is part of what the vendor signs (`token`, address(0) for native QOR), so an
///     invoice for 100 fUSD cannot be paid, or claimed, as 100 of anything else;
///   - ERC-20 invoices are paid with transferFrom(payer -> vendor) against the allowance the payer
///     gave this desk. The desk never holds tokens, and the allowance is one more cap the owner
///     sets: the chain counts the payer's ERC-20 outflow against the rule's per-denom limits.
contract InvoiceDeskV2 {
    IQorePQCv2 constant PQC_VERIFY = IQorePQCv2(0x0000000000000000000000000000000000000a01);
    IQorePQCv2 constant PQC_STATUS = IQorePQCv2(0x0000000000000000000000000000000000000a02);
    uint8 constant ALG_ML_DSA_87 = 1;
    bytes32 constant DOMAIN = keccak256("LEASH-INVOICE-v2");

    /// payer => vendor => approved
    mapping(address => mapping(address => bool)) public approved;
    /// payer => invoice id => paid
    mapping(address => mapping(bytes32 => bool)) public paid;

    event VendorApproved(address indexed payer, address indexed vendor, bool approved);
    event InvoicePaid(address indexed payer, address indexed vendor, bytes32 indexed id, address token, uint256 amount);

    error UnknownVendor(address vendor);
    error VendorKeyNotProven(address vendor);
    error BadSignature();
    error AlreadyPaid(bytes32 id);
    error PastDue(uint64 dueBy);
    error WrongAmount(uint256 sent, uint256 invoiced);
    error TransferFailed();

    function approveVendor(address vendor) external {
        approved[msg.sender][vendor] = true;
        emit VendorApproved(msg.sender, vendor, true);
    }

    function removeVendor(address vendor) external {
        approved[msg.sender][vendor] = false;
        emit VendorApproved(msg.sender, vendor, false);
    }

    /// The exact bytes a vendor signs: domain, chain, this desk, payer, vendor, currency, amount,
    /// invoice id, due date. Readable by anyone so off-chain tools sign the same thing.
    function invoiceMessage(address payer, address vendor, address token, uint256 amount, bytes32 id, uint64 dueBy)
        public view returns (bytes memory)
    {
        return abi.encode(DOMAIN, block.chainid, address(this), payer, vendor, token, amount, id, dueBy);
    }

    /// @param token address(0) for native QOR (send it as msg.value), else the ERC-20 to pay in.
    function pay(address token, address payable vendor, uint256 amount, bytes32 id, uint64 dueBy, bytes calldata signature)
        external payable
    {
        if (!approved[msg.sender][vendor]) revert UnknownVendor(vendor);
        // Signature before "already paid", as in v1: an edited copy of a paid invoice is a forgery.
        if (!PQC_VERIFY.pqcVerify(_vendorKey(vendor), signature, invoiceMessage(msg.sender, vendor, token, amount, id, dueBy))) {
            revert BadSignature();
        }
        if (paid[msg.sender][id]) revert AlreadyPaid(id);
        if (block.timestamp > dueBy) revert PastDue(dueBy);
        uint256 native = token == address(0) ? amount : 0;
        if (msg.value != native) revert WrongAmount(msg.value, native);

        paid[msg.sender][id] = true;
        emit InvoicePaid(msg.sender, vendor, id, token, amount);
        if (token == address(0)) {
            (bool ok,) = vendor.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            // transferFrom(payer, vendor, amount); accept tokens that return nothing or true. A call
            // to an address without code would "succeed" and move nothing, so that is refused first.
            if (token.code.length == 0) revert TransferFailed();
            (bool ok, bytes memory ret) = token.call(abi.encodeWithSelector(0x23b872dd, msg.sender, vendor, amount));
            if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed();
        }
    }

    /// The vendor's ML-DSA-87 public key, read from the chain's PQC module at payment time. Only a
    /// key whose possession was proven at registration counts.
    function _vendorKey(address vendor) internal view returns (bytes memory pubkey) {
        bool registered;
        uint8 alg;
        bool proven;
        (registered, alg, pubkey, proven) = PQC_STATUS.pqcKeyStatus(vendor);
        if (!registered || !proven || alg != ALG_ML_DSA_87) revert VendorKeyNotProven(vendor);
    }
}
