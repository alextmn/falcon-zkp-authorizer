// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IPQCAuthorizer
 * @notice Interface for Post-Quantum Cryptography authorization
 * @dev This interface allows the qLabs token to delegate authorization
 *      decisions to an external contract. This enables upgrading from a
 *      dummy authorizer to a real Falcon-ZKP authorizer without changing
 *      the token contract address.
 */
interface IPQCAuthorizer {
    /**
     * @notice Check if an address is authorized to send tokens
     * @param account The address to check
     * @return authorized True if the account is authorized to transfer tokens
     */
    function isAuthorized(address account) external view returns (bool authorized);

    /**
     * @notice Authorize an upgrade to a new PQC authorizer
     * @dev This function verifies that the upgrade is legitimate using PQC proofs
     * @param sender The address initiating the upgrade
     * @param tokenContract The token contract being upgraded
     * @param currentAuthorizer The current authorizer contract
     * @param newAuthorizer The proposed new authorizer contract
     * @param proof ZKP proof data (empty for dummy authorizer)
     * @return approved True if the upgrade is authorized
     */
    function authorizeUpgrade(
        address sender,
        address tokenContract,
        address currentAuthorizer,
        address newAuthorizer,
        bytes calldata proof
    ) external returns (bool approved);

    /**
     * @notice Emitted when an account's authorization status changes
     * @param account The account whose status changed
     * @param authorized The new authorization status
     */
    event AuthorizationChanged(address indexed account, bool authorized);

    /**
     * @notice Emitted when an upgrade is authorized
     * @param tokenContract The token contract being upgraded
     * @param oldAuthorizer The previous authorizer
     * @param newAuthorizer The new authorizer
     */
    event UpgradeAuthorized(
        address indexed tokenContract,
        address indexed oldAuthorizer,
        address indexed newAuthorizer
    );
}