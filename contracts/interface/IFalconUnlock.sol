// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFalconUnlock {
    function unlock(
        address account,
        uint256[2] calldata pA,
        uint256[2][2] calldata pB,
        uint256[2] calldata pC,
        uint256 userNonce,
        uint256 cHash
    ) external;
}
