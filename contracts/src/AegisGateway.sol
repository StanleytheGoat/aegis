// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title AegisGateway
/// @notice A safety gateway that wraps DeFi interactions with pre-execution checks.
///         Agents route transactions through this contract, which enforces safety
///         attestations and collects a small protocol fee.
/// @dev Designed to work with the Aegis MCP server which provides off-chain simulation
///      and risk scoring. The on-chain component enforces that a valid safety attestation
///      exists before forwarding the call.
contract AegisGateway is Ownable, ReentrancyGuard {

    // --- Events ---
    event TransactionExecuted(
        address indexed agent,
        address indexed target,
        bytes32 indexed attestationId,
        uint256 value,
        uint256 fee,
        uint8 riskScore
    );

    event AttestationRecorded(
        bytes32 indexed attestationId,
        address indexed agent,
        address indexed target,
        uint8 riskScore,
        uint256 timestamp
    );

    event RiskThresholdUpdated(uint8 oldThreshold, uint8 newThreshold);
    event FeeUpdated(uint256 oldFeeBps, uint256 newFeeBps);
    event AttesterUpdated(address oldAttester, address newAttester);
    event FeesWithdrawn(address indexed recipient, uint256 amount);
    event StuckEthRescued(address indexed recipient, uint256 amount);

    // --- Structs ---
    struct SafetyAttestation {
        address agent;       // The agent requesting the transaction
        address target;      // The target contract
        bytes4 selector;     // The function selector being called
        uint8 riskScore;     // 0-100, where 0 is safest
        uint256 timestamp;   // When the attestation was created
        bool used;           // Whether the attestation has been consumed
    }

    // --- State ---
    /// @notice The trusted off-chain attester (Aegis MCP server's signing key)
    address public attester;

    /// @notice Risk score threshold (0-100). Transactions above this are blocked.
    uint8 public riskThreshold = 70;

    /// @notice Protocol fee in basis points (default: 5 bps = 0.05%)
    uint256 public feeBps = 5;

    /// @notice Minimum fee to prevent dust transactions from being free
    uint256 public minFee = 0.0001 ether;

    /// @notice Accumulated protocol fees available for withdrawal
    uint256 public accumulatedFees;

    /// @notice Attestation storage
    mapping(bytes32 => SafetyAttestation) public attestations;

    /// @notice Agent transaction count (for analytics)
    mapping(address => uint256) public agentTxCount;

    /// @notice Agent blocked transaction count
    mapping(address => uint256) public agentBlockedCount;

    /// @notice Immutable fee recipient (cold wallet) - fees can ONLY go here
    address payable public immutable feeRecipient;

    // --- Constructor ---
    constructor(address _attester, address payable _feeRecipient) Ownable(msg.sender) {
        require(_attester != address(0), "Invalid attester");
        require(_feeRecipient != address(0), "Invalid fee recipient");
        attester = _attester;
        feeRecipient = _feeRecipient;
    }

    // --- Core Functions ---

    /// @notice Record a safety attestation from the trusted Aegis MCP server.
    ///         Called off-chain by the attester after simulation + risk analysis.
    ///         Signature includes chain ID and contract address to prevent cross-chain replay.
    function recordAttestation(
        bytes32 attestationId,
        address agent,
        address target,
        bytes4 selector,
        uint8 riskScore,
        bytes calldata signature
    ) external {
        require(attestations[attestationId].timestamp == 0, "Attestation exists");
        require(riskScore <= 100, "Invalid risk score");
        require(agent != address(0), "Invalid agent");
        require(target != address(0), "Invalid target");

        // Verify the attester's signature (includes chain ID + contract address to prevent replay)
        bytes32 messageHash = keccak256(abi.encodePacked(
            attestationId, agent, target, selector, riskScore,
            block.chainid, address(this)
        ));
        bytes32 ethSignedHash = _toEthSignedMessageHash(messageHash);
        address recovered = _recoverSigner(ethSignedHash, signature);
        require(recovered != address(0), "Invalid signature");
        require(recovered == attester, "Invalid attester");

        attestations[attestationId] = SafetyAttestation({
            agent: agent,
            target: target,
            selector: selector,
            riskScore: riskScore,
            timestamp: block.timestamp,
            used: false
        });

        emit AttestationRecorded(attestationId, agent, target, riskScore, block.timestamp);
    }

    /// @notice Execute a transaction through the safety gateway.
    ///         Requires a valid, unused attestation with risk below threshold.
    function executeProtected(
        bytes32 attestationId,
        address target,
        bytes calldata data
    ) external payable nonReentrant {
        SafetyAttestation storage att = attestations[attestationId];

        require(att.timestamp != 0, "No attestation");
        require(!att.used, "Attestation already used");
        require(att.agent == msg.sender, "Not the attested agent");
        require(att.target == target, "Target mismatch");
        require(bytes4(data[:4]) == att.selector, "Selector mismatch");
        require(att.riskScore <= riskThreshold, "Risk too high");
        require(block.timestamp - att.timestamp <= 5 minutes, "Attestation expired");

        // Mark attestation as used (CEI: state before external call)
        att.used = true;

        // Calculate and collect fee (multiply before divide to avoid precision loss)
        uint256 fee = 0;
        if (msg.value > 0) {
            fee = (msg.value * feeBps) / 10_000;
            // Enforce minimum fee if tx value is large enough to cover it
            if (fee < minFee && msg.value > minFee) {
                fee = minFee;
            }
            // Never charge more fee than the transaction value
            if (fee > msg.value) {
                fee = msg.value;
            }
        }
        accumulatedFees += fee;

        // Forward the transaction (safe: fee <= msg.value guaranteed above)
        uint256 forwardValue = msg.value - fee;
        (bool success, bytes memory result) = target.call{value: forwardValue}(data);
        require(success, string(abi.encodePacked("Execution failed: ", result)));

        agentTxCount[msg.sender]++;

        emit TransactionExecuted(
            msg.sender,
            target,
            attestationId,
            msg.value,
            fee,
            att.riskScore
        );
    }

    /// @notice Check if a transaction would be allowed (view function for simulation)
    function wouldAllow(bytes32 attestationId) external view returns (
        bool allowed,
        uint8 riskScore,
        string memory reason
    ) {
        SafetyAttestation storage att = attestations[attestationId];

        if (att.timestamp == 0) return (false, 0, "No attestation found");
        if (att.used) return (false, att.riskScore, "Attestation already used");
        if (att.riskScore > riskThreshold) return (false, att.riskScore, "Risk score too high");
        if (block.timestamp - att.timestamp > 5 minutes) return (false, att.riskScore, "Attestation expired");

        return (true, att.riskScore, "Transaction allowed");
    }

    // --- Admin Functions ---

    function setRiskThreshold(uint8 _threshold) external onlyOwner {
        require(_threshold <= 100, "Invalid threshold");
        emit RiskThresholdUpdated(riskThreshold, _threshold);
        riskThreshold = _threshold;
    }

    function setFeeBps(uint256 _feeBps) external onlyOwner {
        require(_feeBps <= 100, "Fee too high"); // Max 1%
        emit FeeUpdated(feeBps, _feeBps);
        feeBps = _feeBps;
    }

    function setAttester(address _attester) external onlyOwner {
        require(_attester != address(0), "Invalid attester");
        emit AttesterUpdated(attester, _attester);
        attester = _attester;
    }

    /// @notice Withdraw accumulated fees to the immutable feeRecipient (cold wallet).
    ///         Anyone can call this - fees can only ever go to the cold wallet.
    function withdrawFees() external nonReentrant {
        uint256 amount = accumulatedFees;
        require(amount > 0, "No fees to withdraw");
        accumulatedFees = 0;
        (bool success,) = feeRecipient.call{value: amount}("");
        require(success, "Withdrawal failed");
        emit FeesWithdrawn(feeRecipient, amount);
    }

    /// @notice Rescue ETH sent directly to the contract (not through executeProtected).
    ///         Only rescues ETH above accumulatedFees. Goes to feeRecipient.
    function rescueStuckEth() external nonReentrant {
        uint256 stuck = address(this).balance - accumulatedFees;
        require(stuck > 0, "No stuck ETH");
        (bool success,) = feeRecipient.call{value: stuck}("");
        require(success, "Rescue failed");
        emit StuckEthRescued(feeRecipient, stuck);
    }

    // --- Internal Helpers ---

    function _toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function _recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid signature length");
        bytes32 r = bytes32(sig[:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (v < 27) v += 27;
        // EIP-2: reject signatures with s in the upper half of the curve
        require(s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "Invalid s value");
        return ecrecover(hash, v, r, s);
    }

    receive() external payable {}
}
