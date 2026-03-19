// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal contract that accepts ETH. Used for testing fee flow.
contract EthReceiver {
    receive() external payable {}
    fallback() external payable {}
}
