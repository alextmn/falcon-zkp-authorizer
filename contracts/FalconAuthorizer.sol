// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interface/IPQCAuthorizer.sol";
import "./FalconVerifier.sol";

/**
 * @title FalconAuthorizer
 * @notice PQC authorizer using Falcon-ZKP Groth16 proofs.
 *
 * Lifecycle
 * ---------
 * 1. Owner calls `lock(account, pkHash)` to bind an address to a Falcon
 *    public-key hash.  While locked, `isAuthorized(account)` returns false.
 * 2. Anyone holding the Falcon private key produces a ZKP and calls
 *    `unlock(account, pA, pB, pC, txHash1, txHash2)`.  The contract
 *    reconstructs the public signals `[pkHash, txHash1, txHash2]` from
 *    storage and verifies the Groth16 proof.  On success the lock is
 *    removed and `isAuthorized(account)` returns true.
 *
 * Circuit public signals (3):
 *   [0] pk_hash_in   – Poseidon hash of the Falcon public key
 *   [1] in_tx_hash1  – first  128 bits of the transaction hash
 *   [2] in_tx_hash2  – last   128 bits of the transaction hash
 *   [3] c_hash       – 256-bit falcon'schallenge hash
 */
contract FalconAuthorizer is IPQCAuthorizer {

    address public owner;
    Groth16Verifier public immutable verifier;

    uint256[3] public upgradeGuardians;

    mapping(address => uint256) public pkHashes;
    mapping(uint256 => bool)    public usedCHashes;

    error Unauthorized();
    error NotLocked(address account);
    error AlreadyLocked(address account);
    error InvalidProof();
    error ZeroPkHash();
    error NotAGuardian(uint256 pkHash);
    error CHashAlreadyUsed(uint256 cHash);

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    /**
     * @param _verifier  Deployed Groth16Verifier address.
     * @param _guardians Three Falcon public-key hashes whose holders may
     *                   authorize contract upgrades via ZKP.
     */
    constructor(address _verifier, uint256[3] memory _guardians) {
        owner = msg.sender;
        verifier = Groth16Verifier(_verifier);
        upgradeGuardians = _guardians;
    }

    // ─── Lock / Unlock ───────────────────────────────────────────────

    /**
     * @notice Bind `account` to a Falcon public-key hash and mark it locked.
     */
    function lock(address account, uint256 pkHash) external onlyOwner {
        if (pkHash == 0) revert ZeroPkHash();
        if (pkHashes[account] != 0) revert AlreadyLocked(account);

        pkHashes[account] = pkHash;

        emit AuthorizationChanged(account, false);
    }

    /**
     * @notice Verify a Falcon-ZKP Groth16 proof and unlock `account`.
     * @param account  The locked address to unlock.
     * @param pA       Groth16 proof element A.
     * @param pB       Groth16 proof element B.
     * @param pC       Groth16 proof element C.
     * @param cHash    Unique 256-bit challenge hash; split into low/high
     *                 128-bit halves for the circuit's public signals.
     *                 Each cHash may only be used once (replay protection).
     */
    function unlock(
        address account,
        uint[2] calldata pA,
        uint[2][2] calldata pB,
        uint[2] calldata pC,
        uint256 cHash
    ) external {
        uint256 pkHash = pkHashes[account];
        if (pkHash == 0) revert NotLocked(account);
        if (usedCHashes[cHash]) revert CHashAlreadyUsed(cHash);

        (uint256 lo, uint256 hi) = _splitHash(cHash);
        uint[3] memory pubSignals = [pkHash, lo, hi];

        if (!verifier.verifyProof(pA, pB, pC, pubSignals)) {
            revert InvalidProof();
        }

        usedCHashes[cHash] = true;
        pkHashes[account] = 0;

        emit AuthorizationChanged(account, true);
    }

    // ─── IPQCAuthorizer ──────────────────────────────────────────────

    /// @inheritdoc IPQCAuthorizer
    function isAuthorized(address account) external view override returns (bool) {
        return pkHashes[account] == 0;
    }

    /// @inheritdoc IPQCAuthorizer
    function authorizeUpgrade(
        address,
        address tokenContract,
        address currentAuthorizer,
        address newAuthorizer,
        bytes calldata proof
    ) external override returns (bool approved) {
        (
            uint[2] memory pA,
            uint[2][2] memory pB,
            uint[2] memory pC,
            uint[3] memory pubSignals
        ) = abi.decode(proof, (uint[2], uint[2][2], uint[2], uint[3]));

        uint256 pkHash = pubSignals[0];
        if (!_isGuardian(pkHash)) revert NotAGuardian(pkHash);

        if (!verifier.verifyProof(pA, pB, pC, pubSignals)) {
            revert InvalidProof();
        }

        emit UpgradeAuthorized(tokenContract, currentAuthorizer, newAuthorizer);
        return true;
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    function _isGuardian(uint256 pkHash) private view returns (bool) {
        for (uint256 i = 0; i < 3; i++) {
            if (upgradeGuardians[i] == pkHash) return true;
        }
        return false;
    }

    function _splitHash(uint256 h) private pure returns (uint256 lo, uint256 hi) {
        lo = h & type(uint128).max;
        hi = h >> 128;
    }
}
