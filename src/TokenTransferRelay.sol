// SPDX-License-Identifier: MIT
// Unagi Contracts v1.0.0 (TokenTransferRelay.sol)
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Multicall} from "@openzeppelin/contracts/utils/Multicall.sol";

/**
 * @title TokenTransferRelay
 * @dev A two-step transfer service for native tokens and ERC20 tokens that supports refunds.
 *
 * Transfer flow:
 * 1. Token holder reserves a transfer by calling `reserveTransfer` with a signed authorization from an authority, placing funds in escrow
 * 2. Authority executes the transfer with `executeTransfer` to send funds to specified receivers
 * 3. Alternatively, authority can refund the escrowed funds to the original sender with `revertTransfer`
 *
 * Token holders must approve this contract to spend their ERC20 tokens before reserving ERC20 transfers.
 * Authorities must have AUTHORITY_ROLE to execute transfers, revert transfers, and must sign authorization messages for transfer reservations.
 *
 * @custom:security-contact security@unagi.ch
 */
contract TokenTransferRelay is AccessControl, Multicall {
    using SafeERC20 for IERC20;

    bytes32 public constant AUTHORITY_ROLE = keccak256("AUTHORITY_ROLE");

    // Possible states for an existing token transfer
    bytes32 public constant TRANSFER_RESERVED = keccak256("TRANSFER_RESERVED");
    bytes32 public constant TRANSFER_EXECUTED = keccak256("TRANSFER_EXECUTED");
    bytes32 public constant TRANSFER_REVERTED = keccak256("TRANSFER_REVERTED");

    struct Erc20Transfer {
        address erc20Address;
        uint256 erc20Amount;
    }

    mapping(string => bytes32) private _states;
    mapping(string => uint256) private _nativeTransfers;
    mapping(string => Erc20Transfer) private _erc20Transfers;

    constructor(address initialAdmin) {
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
    }

    function getTransferState(string memory uid) public view returns (bytes32) {
        return _states[uid];
    }

    function isNativeTransfer(string memory uid) public view returns (bool) {
        return _nativeTransfers[uid] > 0;
    }

    function getNativeTransfer(string memory uid) public view returns (bytes32, uint256) {
        return (_states[uid], _nativeTransfers[uid]);
    }

    function getErc20Transfer(string memory uid) public view returns (bytes32, Erc20Transfer memory) {
        return (_states[uid], _erc20Transfers[uid]);
    }

    function isErc20Transfer(string memory uid) public view returns (bool) {
        return _erc20Transfers[uid].erc20Amount > 0;
    }

    function isTransferReserved(string memory uid) public view returns (bool) {
        return _states[uid] == TRANSFER_RESERVED;
    }

    function isTransferProcessed(string memory uid) public view returns (bool) {
        return _states[uid] == TRANSFER_EXECUTED || _states[uid] == TRANSFER_REVERTED;
    }

    /**
     * @notice Reserves a native token transfer by placing the sent native tokens in escrow
     * @dev Requires a valid signature from an authority with AUTHORITY_ROLE
     * @param uid Unique identifier for this transfer
     * @param chargeId Identifier for the charge
     * @param signature Signature from an authority authorizing this transfer
     * @param expiration Timestamp after which the signature expires
     * @param authorizer Address of the authority who signed the authorization
     */
    function reserveNativeTransfer(
        string memory uid,
        uint8 chargeId,
        bytes memory signature,
        uint40 expiration,
        address authorizer
    ) external payable {
        require(msg.value > 0, "TokenTransferRelay: Transfer value is null");
        require(!isTransferReserved(uid), "TokenTransferRelay: Transfer already reserved");
        require(!isTransferProcessed(uid), "TokenTransferRelay: Transfer already processed");
        _verifySignature(signature, expiration, authorizer, uid, chargeId, address(0), msg.value);

        _states[uid] = TRANSFER_RESERVED;
        _nativeTransfers[uid] = msg.value;

        emit TransferReserved(uid, chargeId);
    }

    /**
     * @notice Executes a reserved native token transfer by sending escrowed funds to the receiver
     * @dev Can only be called by addresses with AUTHORITY_ROLE
     * @param uid Unique identifier of the transfer to execute
     * @param receiver Address that will receive the native tokens
     * @return success True if the transfer was successful, false otherwise
     */
    function executeNativeTransfer(string memory uid, address receiver)
        external
        onlyRole(AUTHORITY_ROLE)
        returns (bool)
    {
        if (!isTransferReserved(uid) || !isNativeTransfer(uid)) {
            return false;
        }

        _states[uid] = TRANSFER_EXECUTED;

        (bool success,) = receiver.call{value: _nativeTransfers[uid]}("");
        if (!success) {
            _states[uid] = TRANSFER_RESERVED;
            return false;
        }
        emit TransferExecuted(uid);
        return true;
    }

    /**
     * @notice Reverts a reserved native token transfer by sending escrowed funds back to the original sender
     * @dev Can only be called by addresses with AUTHORITY_ROLE. If the refund fails, the transfer remains reserved.
     * @param uid Unique identifier of the transfer to revert
     * @return success True if the refund was successful, false otherwise
     */
    function revertNativeTransfer(string memory uid, address refund) external onlyRole(AUTHORITY_ROLE) returns (bool) {
        if (!isTransferReserved(uid) || !isNativeTransfer(uid)) {
            return false;
        }

        _states[uid] = TRANSFER_REVERTED;

        (bool success,) = refund.call{value: _nativeTransfers[uid]}("");
        if (!success) {
            _states[uid] = TRANSFER_RESERVED;
            return false;
        }
        emit TransferReverted(uid);
        return true;
    }

    /**
     * @notice Reserves an ERC20 token transfer by placing the specified tokens in escrow
     * @dev Requires prior approval for this contract to spend the tokens and a valid signature from an authority
     * @param uid Unique identifier for this transfer
     * @param chargeId Identifier for the charge
     * @param erc20Address Address of the ERC20 token contract
     * @param erc20Amount Amount of tokens to transfer
     * @param signature Signature from an authority authorizing this transfer
     * @param expiration Timestamp after which the signature expires
     * @param authorizer Address of the authority who signed the authorization
     */
    function reserveErc20Transfer(
        string memory uid,
        uint8 chargeId,
        address erc20Address,
        uint256 erc20Amount,
        bytes memory signature,
        uint40 expiration,
        address authorizer
    ) external {
        require(erc20Amount > 0, "TokenTransferRelay: Transfer value is null");
        require(!isTransferReserved(uid), "TokenTransferRelay: Transfer already reserved");
        require(!isTransferProcessed(uid), "TokenTransferRelay: Transfer already processed");
        _verifySignature(signature, expiration, authorizer, uid, chargeId, erc20Address, erc20Amount);

        _states[uid] = TRANSFER_RESERVED;
        _erc20Transfers[uid] = Erc20Transfer(erc20Address, erc20Amount);

        // Place tokens under escrow
        IERC20(erc20Address).safeTransferFrom(msg.sender, address(this), erc20Amount);

        emit TransferReserved(uid, chargeId);
    }

    /**
     * @notice Executes a reserved ERC20 token transfer by sending escrowed tokens to the receiver
     * @dev Can only be called by addresses with AUTHORITY_ROLE
     * @param uid Unique identifier of the transfer to execute
     * @param receiver Address that will receive the ERC20 tokens
     * @return success True if the transfer was successful, false otherwise
     */
    function executeErc20Transfer(string memory uid, address receiver)
        external
        onlyRole(AUTHORITY_ROLE)
        returns (bool)
    {
        if (!isTransferReserved(uid) || !isErc20Transfer(uid)) {
            return false;
        }

        _states[uid] = TRANSFER_EXECUTED;

        bool success = IERC20(_erc20Transfers[uid].erc20Address).transfer(receiver, _erc20Transfers[uid].erc20Amount);
        if (!success) {
            _states[uid] = TRANSFER_RESERVED;
            return false;
        }
        emit TransferExecuted(uid);
        return true;
    }

    /**
     * @notice Reverts a reserved ERC20 token transfer by sending escrowed tokens back to the original sender
     * @dev Can only be called by addresses with AUTHORITY_ROLE. If the refund fails, the transfer remains reserved.
     * @param uid Unique identifier of the transfer to revert
     * @return success True if the refund was successful, false otherwise
     */
    function revertErc20Transfer(string memory uid, address refund) external onlyRole(AUTHORITY_ROLE) returns (bool) {
        if (!isTransferReserved(uid) || !isErc20Transfer(uid)) {
            return false;
        }

        _states[uid] = TRANSFER_REVERTED;

        bool success = IERC20(_erc20Transfers[uid].erc20Address).transfer(refund, _erc20Transfers[uid].erc20Amount);
        if (!success) {
            _states[uid] = TRANSFER_RESERVED;
            return false;
        }

        emit TransferReverted(uid);
        return true;
    }

    /**
     * @notice Internal function to verify a signature from an authority
     * @dev The signature must be signed by an address with AUTHORITY_ROLE and contain:
     * - authorizer address (the authority who signed)
     * - expiration timestamp (must be in the future)
     * - chain ID and contract address (anti-replay protection)
     * - transfer uid (uniqueness)
     * - token address and amount (for ERC20, address(0) for native)
     * @param signature The signature to verify
     * @param expiration Timestamp after which the signature is invalid
     * @param authorizer Address that should have signed the message
     * @param uid Unique identifier for the transfer
     * @param chargeId Identifier for the charge
     * @param tokenAddress Address of the token (address(0) for native tokens)
     * @param tokenAmount Amount of tokens to transfer
     */
    function _verifySignature(
        bytes memory signature,
        uint40 expiration,
        address authorizer,
        string memory uid,
        uint8 chargeId,
        address tokenAddress,
        uint256 tokenAmount
    ) internal view {
        require(hasRole(AUTHORITY_ROLE, authorizer), "TokenTransferRelay: Missing role AUTHORITY_ROLE for authorizer");
        require(block.timestamp <= expiration, "TokenTransferRelay: Signature expired");
        require(
            SignatureChecker.isValidSignatureNow(
                authorizer,
                MessageHashUtils.toEthSignedMessageHash(
                    keccak256(
                        abi.encodePacked(
                            authorizer,
                            expiration,
                            block.chainid,
                            address(this),
                            uid,
                            chargeId,
                            tokenAddress,
                            tokenAmount
                        )
                    )
                ),
                signature
            ),
            "TokenTransferRelay: Invalid Signature"
        );
    }

    event TransferReserved(string indexed uid, uint8 chargeId);
    event TransferExecuted(string uid);
    event TransferReverted(string uid);
}
