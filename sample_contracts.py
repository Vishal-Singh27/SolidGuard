SAMPLE_CONTRACTS = {
    "VulnerableBank (DAO Reentrancy Exploit)": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY: SWC-107 Reentrancy
    // External call performed BEFORE balance update
    function withdrawAll() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        balances[msg.sender] = 0; // State change happens too late!
    }

    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}""",

    "PhishingWallet (tx.origin Authentication Flaw)": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PhishingWallet {
    address public owner;

    constructor() payable {
        owner = msg.sender;
    }

    // VULNERABILITY: SWC-115 Authorization through tx.origin
    // Phishing contract can trick owner into triggering this transfer
    function transferTo(address payable _to, uint256 _amount) public {
        require(tx.origin == owner, "Only owner can transfer");

        (bool success, ) = _to.call{value: _amount}("");
        require(success, "Transfer failed");
    }

    receive() external payable {}
}""",

    "UnprotectedAdminVault (Missing Access Control)": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UnprotectedAdminVault {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    // VULNERABILITY: SWC-105 Unprotected Ether Withdrawal
    // Missing onlyOwner or access restriction modifier
    function emergencyDrain(address payable recipient) public {
        // Missing: require(msg.sender == admin, "Not admin");
        recipient.transfer(address(this).balance);
    }

    // VULNERABILITY: SWC-106 Unprotected Selfdestruct
    function kill() public {
        selfdestruct(payable(msg.sender));
    }

    receive() external payable {}
}""",

    "SecureVault (Remediated Best Practice)": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

contract SecureVault is ReentrancyGuard {
    address public immutable owner;
    mapping(address => uint256) public balances;

    event Deposit(address indexed sender, uint256 amount);
    event Withdrawal(address indexed recipient, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized: Caller is not owner");
        _;
    }

    function deposit() external payable {
        require(msg.value > 0, "Deposit amount must be > 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // CHECKS-EFFECTS-INTERACTIONS + nonReentrant modifier
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // 1. Effects: State updated BEFORE external call
        balances[msg.sender] -= amount;

        // 2. Interactions: Safe low-level transfer
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "ETH transfer failed");

        emit Withdrawal(msg.sender, amount);
    }
}"""
}
