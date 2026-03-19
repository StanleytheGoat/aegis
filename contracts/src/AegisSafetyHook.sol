// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/src/utils/BaseHook.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/src/types/BeforeSwapDelta.sol";
import {Currency} from "v4-core/src/types/Currency.sol";

/// @title AegisSafetyHook
/// @notice A Uniswap v4 hook that enforces pre-swap safety checks.
///         Works with the Aegis MCP server to protect AI agents from
///         interacting with malicious tokens or dangerous pools.
///
/// How it works:
/// 1. Agent calls Aegis MCP server to assess risk of a swap
/// 2. If safe, Aegis server signs an attestation and records it on-chain
/// 3. Agent initiates swap, passing attestation ID in hookData
/// 4. beforeSwap checks the attestation is valid and risk is below threshold
/// 5. If no valid attestation exists, the swap is blocked
///
/// This creates a trust layer where AI agents can autonomously trade
/// while being protected from scams, honeypots, and exploits.
contract AegisSafetyHook is BaseHook {
    using PoolIdLibrary for PoolKey;

    // --- Events ---
    event SwapProtected(
        PoolId indexed poolId,
        address indexed swapper,
        bytes32 attestationId,
        uint8 riskScore
    );

    event SwapBlocked(
        PoolId indexed poolId,
        address indexed swapper,
        string reason
    );

    event TokenFlagged(address indexed token, uint8 riskScore, string reason);
    event TokenCleared(address indexed token);

    // --- Structs ---
    struct SafetyAttestation {
        address agent;
        uint8 riskScore;
        uint256 expiresAt;
        bool used;
    }

    // --- State ---
    /// @notice Trusted attester address (Aegis MCP server's signing key)
    address public immutable attester;

    /// @notice Risk threshold (0-100). Swaps with risk above this are blocked.
    uint8 public riskThreshold = 70;

    /// @notice Attestation storage
    mapping(bytes32 => SafetyAttestation) public attestations;

    /// @notice Flagged tokens that should always be blocked
    mapping(address => bool) public flaggedTokens;

    /// @notice Per-pool swap counters (for analytics)
    mapping(PoolId => uint256) public protectedSwapCount;
    mapping(PoolId => uint256) public blockedSwapCount;

    /// @notice Whether to allow swaps without attestations (permissive mode)
    bool public permissiveMode;

    /// @notice Owner for admin functions
    address public owner;

    // --- Errors ---
    error NotOwner();
    error NoAttestation();
    error AttestationExpired();
    error AttestationUsed();
    error RiskTooHigh(uint8 riskScore, uint8 threshold);
    error TokenFlaggedAsDangerous(address token);
    error InvalidAttester();

    constructor(IPoolManager _poolManager, address _attester) BaseHook(_poolManager) {
        attester = _attester;
        owner = msg.sender;
    }

    // --- Hook Permissions ---
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true,          // Core: check attestation before swap
            afterSwap: true,           // Analytics: record swap completion
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // --- Core Hook Logic ---

    /// @notice Called before every swap. Checks for valid Aegis safety attestation.
    /// @param sender The address initiating the swap
    /// @param key The pool being swapped on
    /// @param hookData Encoded attestation ID and signature from Aegis MCP server
    function _beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata,
        bytes calldata hookData
    ) internal override returns (bytes4, BeforeSwapDelta, uint24) {
        PoolId poolId = key.toId();

        // Check if either token in the pool is flagged
        address token0 = Currency.unwrap(key.currency0);
        address token1 = Currency.unwrap(key.currency1);

        if (flaggedTokens[token0]) {
            blockedSwapCount[poolId]++;
            emit SwapBlocked(poolId, sender, "Token0 flagged as dangerous");
            revert TokenFlaggedAsDangerous(token0);
        }
        if (flaggedTokens[token1]) {
            blockedSwapCount[poolId]++;
            emit SwapBlocked(poolId, sender, "Token1 flagged as dangerous");
            revert TokenFlaggedAsDangerous(token1);
        }

        // If no hookData provided, check permissive mode
        if (hookData.length == 0) {
            if (permissiveMode) {
                return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
            }
            blockedSwapCount[poolId]++;
            emit SwapBlocked(poolId, sender, "No attestation provided");
            revert NoAttestation();
        }

        // Decode attestation from hookData
        (bytes32 attestationId, bytes memory signature) = abi.decode(hookData, (bytes32, bytes));

        SafetyAttestation storage att = attestations[attestationId];

        // If attestation doesn't exist on-chain yet, verify inline from signature
        if (att.expiresAt == 0) {
            // Reconstruct and verify the attester's signature
            (address agent, uint8 riskScore, uint256 expiresAt) = _verifyAttestation(
                attestationId, signature
            );

            // Store it
            att.agent = agent;
            att.riskScore = riskScore;
            att.expiresAt = expiresAt;
        }

        // Validate attestation
        if (att.used) {
            blockedSwapCount[poolId]++;
            revert AttestationUsed();
        }
        if (block.timestamp > att.expiresAt) {
            blockedSwapCount[poolId]++;
            revert AttestationExpired();
        }
        if (att.riskScore > riskThreshold) {
            blockedSwapCount[poolId]++;
            emit SwapBlocked(poolId, sender, "Risk score too high");
            revert RiskTooHigh(att.riskScore, riskThreshold);
        }

        // Mark attestation as used
        att.used = true;

        emit SwapProtected(poolId, sender, attestationId, att.riskScore);

        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    /// @notice Called after every swap. Records analytics.
    function _afterSwap(
        address,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata,
        BalanceDelta,
        bytes calldata
    ) internal override returns (bytes4, int128) {
        protectedSwapCount[key.toId()]++;
        return (BaseHook.afterSwap.selector, 0);
    }

    // --- Attestation Management ---

    /// @notice Record a safety attestation (can be called by anyone, verified by signature)
    function recordAttestation(
        bytes32 attestationId,
        address agent,
        uint8 riskScore,
        uint256 expiresAt,
        bytes calldata signature
    ) external {
        require(attestations[attestationId].expiresAt == 0, "Already exists");

        bytes32 messageHash = keccak256(abi.encodePacked(
            attestationId, agent, riskScore, expiresAt
        ));
        bytes32 ethSignedHash = _toEthSignedMessageHash(messageHash);
        require(_recoverSigner(ethSignedHash, signature) == attester, "Invalid attester");

        attestations[attestationId] = SafetyAttestation({
            agent: agent,
            riskScore: riskScore,
            expiresAt: expiresAt,
            used: false
        });
    }

    // --- Admin Functions ---

    function flagToken(address token, uint8 riskScore, string calldata reason) external {
        if (msg.sender != owner && msg.sender != attester) revert NotOwner();
        flaggedTokens[token] = true;
        emit TokenFlagged(token, riskScore, reason);
    }

    function clearToken(address token) external {
        if (msg.sender != owner) revert NotOwner();
        flaggedTokens[token] = false;
        emit TokenCleared(token);
    }

    function setRiskThreshold(uint8 _threshold) external {
        if (msg.sender != owner) revert NotOwner();
        require(_threshold <= 100, "Invalid threshold");
        riskThreshold = _threshold;
    }

    function setPermissiveMode(bool _permissive) external {
        if (msg.sender != owner) revert NotOwner();
        permissiveMode = _permissive;
    }

    // --- Internal Helpers ---

    function _verifyAttestation(
        bytes32 attestationId,
        bytes memory signature
    ) internal view returns (address agent, uint8 riskScore, uint256 expiresAt) {
        // Decode the attestation data from the ID
        // In practice, the MCP server encodes: agent, riskScore, expiresAt into a signed message
        // For the hook, we verify the signature matches the attester
        require(signature.length == 65, "Invalid signature");

        // The attestation ID encodes the parameters
        // Signature covers: attestationId
        bytes32 messageHash = keccak256(abi.encodePacked(attestationId));
        bytes32 ethSignedHash = _toEthSignedMessageHash(messageHash);
        address signer = _recoverSigner(ethSignedHash, signature);

        if (signer != attester) revert InvalidAttester();

        // Default values for inline attestations
        return (msg.sender, 0, block.timestamp + 5 minutes);
    }

    function _toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function _recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        return ecrecover(hash, v, r, s);
    }
}
