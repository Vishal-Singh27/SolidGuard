# 🛡️ SolidGuard — RAG-Powered Smart Contract Security Auditor

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-FF4B4B.svg)](https://streamlit.io/)
[![Solidity](https://img.shields.io/badge/Solidity-^0.8.x-363636.svg)](https://soliditylang.org/)
[![Security Standard](https://img.shields.io/badge/Security-SWC%20Registry-059669.svg)](https://swcregistry.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Automated smart contract vulnerability scanner combining Abstract Syntax Tree (AST) static pattern detection and RAG retrieval over official Smart Contract Weakness Classification (SWC) standards.**

---

## 🌟 Overview
Smart contract hacks account for billions of dollars in lost on-chain capital. **SolidGuard** automates pre-deployment security auditing for EVM-compatible contracts (Ethereum, Polygon, Arbitrum). By combining line-level static AST heuristics with an embedded vectorized SWC knowledge base, SolidGuard identifies vulnerabilities, scores contract security from 0 to 100, and provides side-by-side hardened remediations adhering to the **Checks-Effects-Interactions** pattern.

---

## 🚀 Key Features

- **⚡ Multi-Vulnerability Detection**:
  - `SWC-107`: **Reentrancy** (detects state modifications occurring after low-level `.call{value: ...}`)
  - `SWC-115`: **Phishing Authorization via `tx.origin`** (flags vulnerable access control checks)
  - `SWC-105`: **Unprotected Ether Drain** (identifies functions transferring funds without modifiers)
  - `SWC-106`: **Unprotected `selfdestruct`** (flags contract destruction anti-patterns)
  - `SWC-116`: **Block Timestamp Dependence** (flags unsafe PRNG using `block.timestamp`)
  - `SWC-104`: **Unchecked Call Return Value**
- **📊 0–100 Composite Security Score**: Weighted scoring system reflecting vulnerability severity (Critical: -35, High: -20, Medium: -10, Low: -5).
- **🔍 Line-Level Pinpointing**: Exact line number highlighting with offending code snippets.
- **⚖️ Side-by-Side Remediation Diff**: Interactive view showing vulnerable code vs. production-hardened implementation (`nonReentrant` + OpenZeppelin patterns).
- **📥 Audit Report Generation**: One-click downloadable Markdown report for dev teams and auditors.
- **📂 Pre-Loaded Test Contracts**: Includes one-click test suites (`VulnerableBank`, `PhishingWallet`, `UnprotectedAdminVault`, and hardened `SecureVault`).

---

## 🏗️ System Architecture

```
[ Solidity Source (.sol) ]
            │
            ├──► [ AST & Regex Pattern Matcher ] ───► [ Offending Line Extraction ]
            │                                                      │
            └──► [ SWC Knowledge Base (JSON DB) ] ──► [ Semantic Vulnerability Mapping ]
                                                                   │
                                                                   ▼
                                                   [ Composite Audit Engine ]
                                                                   │
                              ┌────────────────────────────────────┴────────────────────────────────────┐
                              ▼                                                                         ▼
                [ Security Score Gauge (0-100) ]                                       [ Remediation Diffs & Report ]
```

---

## 🛠️ Tech Stack
- **Frontend / Interface**: Streamlit with custom CSS cards and metric tiles
- **Static Analysis Engine**: Python AST-level lexical parser & regex pattern matching
- **Knowledge Base**: SWC Registry + ConsenSys Best Practices catalog
- **Target Environments**: EVM Networks (Ethereum, Polygon, Hyperledger Fabric, Layer 2s)

---

## 📦 Project Structure
```
SolidGuard/
├── app.py                      # Main Streamlit application
├── analyzer.py                 # Core AST & SWC audit engine
├── sample_contracts.py         # Built-in vulnerable & safe contracts
├── knowledge_base/
│   └── swc_registry.json       # SWC definitions & remediations
├── requirements.txt            # Python dependencies
├── .streamlit/
│   └── config.toml             # Theme & UI configuration
└── README.md
```

---

## ⚡ Quickstart

### Local Setup
```bash
# 1. Clone the repository
git clone https://github.com/Vishal-Singh27/SolidGuard.git
cd SolidGuard

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the Streamlit application
streamlit run app.py
```

Open your browser at `http://localhost:8501`.

---

## 🎯 Alignment with Datopic Technologies
Datopic engineers decentralized applications and smart contracts across Ethereum, Polygon, and Hyperledger, emphasizing gas optimization and security audits. **SolidGuard demonstrates practical competence in identifying smart contract attack surfaces and enforcing defensive design patterns.**

---

## 📄 License
This project is licensed under the MIT License.
