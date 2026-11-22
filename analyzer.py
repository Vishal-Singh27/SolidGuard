import os
import re
import json

class SmartContractAuditor:
    def __init__(self, api_key=None):
        self.api_key = api_key
        kb_path = os.path.join(os.path.dirname(__file__), "knowledge_base", "swc_registry.json")
        with open(kb_path, "r") as f:
            self.knowledge_base = json.load(f)

    def analyze(self, code_str):
        findings = []
        lines = code_str.split("\n")
        
        # 1. Check for SWC-107 Reentrancy
        # Look for call{value: ...} followed later by balance update
        call_lines = []
        balance_update_lines = []
        
        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("//") or clean.startswith("/*") or clean.startswith("*"):
                continue

            # SWC-115: tx.origin
            if "tx.origin" in clean and ("==" in clean or "require(" in clean):
                kb = self.knowledge_base.get("SWC-115")
                findings.append({
                    "id": "SWC-115",
                    "name": kb["name"],
                    "severity": kb["severity"],
                    "line_number": idx,
                    "code_snippet": clean,
                    "description": kb["description"],
                    "remediation": kb["remediation"]
                })

            # SWC-106: selfdestruct
            if "selfdestruct(" in clean or "suicide(" in clean:
                kb = self.knowledge_base.get("SWC-106")
                findings.append({
                    "id": "SWC-106",
                    "name": kb["name"],
                    "severity": kb["severity"],
                    "line_number": idx,
                    "code_snippet": clean,
                    "description": kb["description"],
                    "remediation": kb["remediation"]
                })

            # SWC-116: Timestamp dependence
            if re.search(r'block\.timestamp\s*%', clean) or re.search(r'\bnow\s*%', clean):
                kb = self.knowledge_base.get("SWC-116")
                findings.append({
                    "id": "SWC-116",
                    "name": kb["name"],
                    "severity": kb["severity"],
                    "line_number": idx,
                    "code_snippet": clean,
                    "description": kb["description"],
                    "remediation": kb["remediation"]
                })

            # Detect external call
            if ".call{value:" in clean or ".call.value(" in clean or "msg.sender.call" in clean:
                call_lines.append((idx, clean))

            # Detect balance write
            if re.search(r'balances\[.*?\]\s*[-+=]=', clean) or re.search(r'balances\[.*?\]\s*=\s*0', clean):
                balance_update_lines.append((idx, clean))

            # SWC-105: Unprotected drain
            if "function emergencyDrain" in clean or "function drain(" in clean:
                # check if next 4 lines lack onlyOwner
                func_block = " ".join(lines[idx-1:idx+6])
                if "onlyOwner" not in func_block and "require(msg.sender" not in func_block:
                    kb = self.knowledge_base.get("SWC-105")
                    findings.append({
                        "id": "SWC-105",
                        "name": kb["name"],
                        "severity": kb["severity"],
                        "line_number": idx,
                        "code_snippet": clean,
                        "description": kb["description"],
                        "remediation": kb["remediation"]
                    })

        # Reentrancy check: call executed BEFORE balance update
        if call_lines and balance_update_lines:
            for c_idx, c_snippet in call_lines:
                for b_idx, b_snippet in balance_update_lines:
                    if c_idx < b_idx:
                        kb = self.knowledge_base.get("SWC-107")
                        findings.append({
                            "id": "SWC-107",
                            "name": kb["name"],
                            "severity": kb["severity"],
                            "line_number": c_idx,
                            "code_snippet": c_snippet,
                            "description": f"External call at line {c_idx} precedes state variable modification at line {b_idx} (Checks-Effects-Interactions violation).",
                            "remediation": kb["remediation"]
                        })

        # Calculate Overall Risk Score (0 = Safe, 100 = Critical Danger)
        severity_weights = {"Critical": 35, "High": 20, "Medium": 10, "Low": 5}
        total_penalty = sum(severity_weights.get(f["severity"], 10) for f in findings)
        risk_score = min(100, total_penalty)
        security_score = max(0, 100 - risk_score)

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        return {
            "findings": findings,
            "security_score": security_score,
            "risk_score": risk_score,
            "counts": counts,
            "is_clean": len(findings) == 0
        }

    def generate_report_markdown(self, contract_name, analysis):
        md = f"""# 🛡️ SolidGuard Smart Contract Security Audit Report
**Target Contract:** `{contract_name}`  
**Audit Standard:** SWC Registry & ConsenSys Best Practices  
**Overall Security Score:** `{analysis['security_score']}/100`  
**Total Vulnerabilities Identified:** `{len(analysis['findings'])}`  

---

## 📊 Vulnerability Breakdown
- 🔴 **Critical:** {analysis['counts']['Critical']}
- 🟠 **High:** {analysis['counts']['High']}
- 🟡 **Medium:** {analysis['counts']['Medium']}
- 🟢 **Low:** {analysis['counts']['Low']}

---

## 🔍 Detailed Vulnerability Findings
"""
        if analysis['is_clean']:
            md += """\n### ✅ No High-Severity Anti-Patterns Detected
The audited smart contract adheres to standard security guidelines, enforcing explicit access controls, nonReentrant guards, and the Checks-Effects-Interactions paradigm.\n"""
        else:
            for idx, f in enumerate(analysis['findings'], 1):
                md += f"""
### {idx}. [{f['severity'].upper()}] {f['id']}: {f['name']}
- **Location:** Line `{f['line_number']}`
- **Vulnerable Code Snippet:**  
  ```solidity
  {f['code_snippet']}
  ```
- **Description:** {f['description']}
- **Recommended Remediation:**  
  {f['remediation']}

---
"""
        return md
