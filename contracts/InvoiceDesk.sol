// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// QoreChain post-quantum precompiles (diana testnet).
interface IQorePQC {
    function pqcVerify(bytes calldata pubkey, bytes calldata signature, bytes calldata message)
        external view returns (bool valid);
    function pqcKeyStatus(address account)
        external view returns (bool registered, uint8 algorithmId, bytes memory pubkey, bool possessionProven);
}

/// @title InvoiceDesk
/// @notice Pays an invoice only when it is signed with ML-DSA-87 by a vendor the payer approved.
///
/// The agent that calls `pay` acts AS the payer's account (QoreChain account abstraction), so
/// `msg.sender` is the payer, not the agent. That is why the agent's on-chain rule scopes it to
/// the `pay` selector alone: it can never reach `approveVendor` / `removeVendor`, even though the
/// contract would accept those calls from the payer's address.
///
/// What `pay` checks, all on chain:
///   1. the vendor is on the payer's own approved list;
///   2. the vendor has an ML-DSA-87 key registered on chain WITH proof of possession;
///   3. that key signed exactly these invoice fields (payer, vendor, amount, id, due date,
///      this desk, this chain), so an amount or a recipient cannot be edited after signing;
///   4. the invoice has not been paid before and is not past due.
/// The value limits (per payment, per day) are not here: the chain's spending rule on the
/// payer's account enforces them before this contract ever runs.
contract InvoiceDesk {
    IQorePQC constant PQC_VERIFY = IQorePQC(0x0000000000000000000000000000000000000a01);
    IQorePQC constant PQC_STATUS = IQorePQC(0x0000000000000000000000000000000000000a02);
    uint8 constant ALG_ML_DSA_87 = 1;
    bytes32 constant DOMAIN = keccak256("LEASH-INVOICE-v1");

    /// payer => vendor => approved
    mapping(address => mapping(address => bool)) public approved;
    /// payer => invoice id => paid
    mapping(address => mapping(bytes32 => bool)) public paid;

    event VendorApproved(address indexed payer, address indexed vendor, bool approved);
    event InvoicePaid(address indexed payer, address indexed vendor, bytes32 indexed id, uint256 amount);

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

    /// The exact bytes a vendor signs. Readable by anyone so off-chain tools sign the same thing.
    function invoiceMessage(address payer, address vendor, uint256 amount, bytes32 id, uint64 dueBy)
        public view returns (bytes memory)
    {
        return abi.encode(DOMAIN, block.chainid, address(this), payer, vendor, amount, id, dueBy);
    }

    function pay(address payable vendor, uint256 amount, bytes32 id, uint64 dueBy, bytes calldata signature)
        external payable
    {
        if (!approved[msg.sender][vendor]) revert UnknownVendor(vendor);
        // The signature is checked before "already paid" on purpose: an edited copy of a paid
        // invoice is reported as the forgery it is, not as a harmless duplicate.
        bytes memory message = invoiceMessage(msg.sender, vendor, amount, id, dueBy);
        if (!PQC_VERIFY.pqcVerify(_vendorKey(vendor), signature, message)) revert BadSignature();
        if (paid[msg.sender][id]) revert AlreadyPaid(id);
        if (block.timestamp > dueBy) revert PastDue(dueBy);
        if (msg.value != amount) revert WrongAmount(msg.value, amount);

        paid[msg.sender][id] = true;
        emit InvoicePaid(msg.sender, vendor, id, amount);
        (bool ok,) = vendor.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// The vendor's ML-DSA-87 public key, read from the chain's PQC module. Only a key whose
    /// possession was proven at registration counts.
    function _vendorKey(address vendor) internal view returns (bytes memory pubkey) {
        bool registered;
        uint8 alg;
        bool proven;
        (registered, alg, pubkey, proven) = PQC_STATUS.pqcKeyStatus(vendor);
        if (!registered || !proven || alg != ALG_ML_DSA_87) revert VendorKeyNotProven(vendor);
    }
}
