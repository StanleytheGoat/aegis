// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title MockHoneypot
/// @notice A deliberately malicious token contract for demo/testing purposes.
///         Implements common honeypot patterns that Aegis should detect:
///         1. Buy tax is 0% but sell tax is 99%
///         2. Owner can pause selling for non-whitelisted addresses
///         3. Hidden max transaction amount that blocks large sells
///         4. Fake renounced ownership (owner() returns address(0) but real owner exists)
/// @dev DO NOT deploy this to mainnet. For Aegis demo and testing only.
contract MockHoneypot {
    string public name = "Totally Safe Token";
    string public symbol = "SAFE";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // Honeypot mechanics
    address private _realOwner;
    bool public sellPaused;
    uint256 public sellTaxBps = 9900; // 99% sell tax
    uint256 public maxSellAmount;
    mapping(address => bool) public whitelisted;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() {
        _realOwner = msg.sender;
        whitelisted[msg.sender] = true;
        totalSupply = 1_000_000_000 * 1e18;
        balanceOf[msg.sender] = totalSupply;
        maxSellAmount = totalSupply / 100; // 1% max sell
    }

    /// @notice Looks like ownership is renounced, but _realOwner still has control
    function owner() external pure returns (address) {
        return address(0); // Fake renounce
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return _transfer(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 currentAllowance = allowance[from][msg.sender];
        require(currentAllowance >= amount, "Insufficient allowance");
        allowance[from][msg.sender] = currentAllowance - amount;
        return _transfer(from, to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");

        // Honeypot: if selling (transferring to a pair/router), apply restrictions
        bool isSell = _isLikelyDex(to);

        if (isSell && !whitelisted[from]) {
            require(!sellPaused, "Trading paused");
            require(amount <= maxSellAmount, "Exceeds max sell");

            // Apply 99% sell tax
            uint256 tax = (amount * sellTaxBps) / 10_000;
            uint256 afterTax = amount - tax;

            balanceOf[from] -= amount;
            balanceOf[to] += afterTax;
            balanceOf[_realOwner] += tax;

            emit Transfer(from, to, afterTax);
            emit Transfer(from, _realOwner, tax);
        } else {
            // No tax on buys (to lure people in)
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
            emit Transfer(from, to, amount);
        }

        return true;
    }

    // Heuristic: addresses with code are likely DEX contracts
    function _isLikelyDex(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    // Hidden admin functions
    function pauseSelling() external {
        require(msg.sender == _realOwner, "Not owner");
        sellPaused = true;
    }

    function setSellTax(uint256 bps) external {
        require(msg.sender == _realOwner, "Not owner");
        sellTaxBps = bps;
    }

    function setMaxSell(uint256 amount) external {
        require(msg.sender == _realOwner, "Not owner");
        maxSellAmount = amount;
    }

    function whitelist(address addr, bool status) external {
        require(msg.sender == _realOwner, "Not owner");
        whitelisted[addr] = status;
    }
}
