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
 * 2. Prover picks `userNonce` and a separate `cHash`, builds the ZKP with
 *    public inputs `[pkHash, lo, hi]` where `computeTxHash(userNonce)` splits
 *    into low/high 128-bit halves, then calls `unlock(..., userNonce, cHash)`.
 *
 * Circuit public signals (3):
 *   [0] pk_hash_in   – hash of the Falcon public key
 *   [1] in_tx_hash1  – low  128 bits of `computeTxHash(userNonce)`
 *   [2] in_tx_hash2  – high 128 bits of `computeTxHash(userNonce)`
 *
 * `cHash` is separate from the tx hash (future ZKP binding); each `cHash`
 * and each `userNonce` may only be consumed once.
 */
contract FalconAuthorizer is IPQCAuthorizer {

    /// @dev Domain tag for `computeTxHash`; must match prover / off-chain tooling.
    string public constant TX_HASH_DOMAIN = "QLABS_ZKP_FALCON_V1";

    address public owner;
    Groth16Verifier public immutable verifier;

    uint256[3] public upgradeGuardians;

    mapping(address => uint256) public pkHashes;
    mapping(uint256 => bool)    public usedUserNonces;
    mapping(uint256 => bool)    public usedCHashes;

    error Unauthorized();
    error NotLocked(address account);
    error AlreadyLocked(address account);
    error InvalidProof();
    error ZeroPkHash();
    error NotAGuardian(uint256 pkHash);
    error CHashAlreadyUsed(uint256 cHash);
    error UserNonceAlreadyUsed(uint256 userNonce);

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

    // ─── Tx hash (challenge binding) ─────────────────────────────────

    /**
     * @notice 256-bit tx hash from `userNonce` (split into two 128-bit circuit public inputs).
     * @dev Preimage: `TX_HASH_DOMAIN` (UTF-8) || chainId (uint256) || this (address) || userNonce (uint256).
     *      `cHash` is not part of this preimage; it is passed separately to `unlock`.
     */
    function computeTxHash(uint256 userNonce) public view returns (uint256) {
        return uint256(
            keccak256(
                abi.encodePacked(TX_HASH_DOMAIN, block.chainid, address(this), userNonce)
            )
        );
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
     * @param pC         Groth16 proof element C.
     * @param userNonce  Binds the tx hash via `computeTxHash(userNonce)` (public inputs lo/hi).
     * @param cHash      Separate challenge id; must be unique per use (future ZKP binding).
     */
    function unlock(
        address account,
        uint[2] calldata pA,
        uint[2][2] calldata pB,
        uint[2] calldata pC,
        uint256 userNonce,
        uint256 cHash
    ) external {
        uint256 pkHash = pkHashes[account];
        if (pkHash == 0) revert NotLocked(account);
        if (usedUserNonces[userNonce]) revert UserNonceAlreadyUsed(userNonce);
        if (usedCHashes[cHash]) revert CHashAlreadyUsed(cHash);

        uint256 txHash = computeTxHash(userNonce);
        (uint256 lo, uint256 hi) = _splitHash(txHash);
        uint[3] memory pubSignals = [pkHash, hi, lo];


        if (!verifier.verifyProof(pA, pB, pC, pubSignals)) {
            revert InvalidProof();
        }

        usedUserNonces[userNonce] = true;
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
            uint[3] memory upgradeHashes
        ) = abi.decode(proof, (uint[2], uint[2][2], uint[2], uint[3]));

        uint256 pkHash = upgradeHashes[0];
        uint256 userNonce = upgradeHashes[1];
        uint256 cHash = upgradeHashes[2];
        if (!_isGuardian(pkHash)) revert NotAGuardian(pkHash);
        if (usedCHashes[cHash]) revert CHashAlreadyUsed(cHash);
        if (usedUserNonces[userNonce]) revert UserNonceAlreadyUsed(userNonce);
        uint256 txHash = computeTxHash(userNonce);
        (uint256 lo, uint256 hi) = _splitHash(txHash);

        // todo: add cHash to the public signals
        if (!verifier.verifyProof(pA, pB, pC, [pkHash, hi, lo])) {
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
