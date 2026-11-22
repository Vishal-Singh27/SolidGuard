import streamlit as st
import json
import os
from analyzer import SmartContractAuditor
from sample_contracts import SAMPLE_CONTRACTS

st.set_page_config(
    page_title="SolidGuard — RAG Smart Contract Vulnerability Auditor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .title-banner {
        font-size: 2.2rem;
        font-weight: 700;
        color: #065F46;
        margin-bottom: 0.2rem;
    }
    .sub-banner {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background-color: #F9FAFB;
        border-radius: 8px;
        padding: 12px;
        border: 1px solid #E5E7EB;
        text-align: center;
    }
    .badge-critical {
        background-color: #FDE8E8;
        color: #9B1C1C;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-high {
        background-color: #FDF6B2;
        color: #723B13;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
    .badge-clean {
        background-color: #DEF7EC;
        color: #03543F;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
    }
</style>
""", unsafe_allow_html=True)

auditor = SmartContractAuditor()

# Sidebar
with st.sidebar:
    st.markdown("### ⚙️ Audit Configuration")
    standard = st.selectbox("Vulnerability Standard", ["SWC Registry + ConsenSys 2026", "EVM Static Patterns"])
    
    st.markdown("---")
    st.markdown("### 📂 Preloaded Vulnerable Contracts")
    sample_key = st.selectbox("Load Sample Contract:", ["-- Choose a Contract --"] + list(SAMPLE_CONTRACTS.keys()))

    st.markdown("---")
    st.markdown("### 🛡️ About SolidGuard")
    st.caption("Automated Smart Contract Auditor combining RAG knowledge retrieval and AST static analysis to secure Web3 protocols.")

# Header
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.markdown('<div class="title-banner">🛡️ SolidGuard</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-banner">RAG-Powered Smart Contract Security Auditor & Vulnerability Scanner</div>', unsafe_allow_html=True)
with col_h2:
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<span class="badge-clean">⚡ Audit Engine: Active (SWC-v2.1)</span>', unsafe_allow_html=True)

tabs = st.tabs(["🔍 Interactive Scanner", "📚 SWC Knowledge Base", "⚖️ Safe vs Vulnerable Code Diff", "🏗️ Architecture"])

# ================= TAB 1: INTERACTIVE SCANNER =================
with tabs[0]:
    col_code, col_report = st.columns([1, 1], gap="medium")

    with col_code:
        st.subheader("1. Solidity Source Code")
        
        default_code = SAMPLE_CONTRACTS["VulnerableBank (DAO Reentrancy Exploit)"]
        if sample_key != "-- Choose a Contract --":
            default_code = SAMPLE_CONTRACTS[sample_key]

        uploaded_sol = st.file_uploader("Upload .sol file", type=["sol"])
        if uploaded_sol:
            default_code = uploaded_sol.read().decode("utf-8")

        contract_input = st.text_area("Solidity Contract:", value=default_code, height=450, placeholder="Paste Solidity code here...")
        
        btn_scan = st.button("🚀 Run Comprehensive Security Audit", type="primary", use_container_width=True)

    with col_report:
        st.subheader("2. Security Audit Findings")

        if btn_scan or sample_key != "-- Choose a Contract --":
            analysis = auditor.analyze(contract_input)
            
            # Security Score & Metric Cards
            score = analysis["security_score"]
            c_score, c_crit, c_high, c_med = st.columns(4)
            with c_score:
                st.metric("Security Score", f"{score}/100")
            with c_crit:
                st.metric("Critical", analysis["counts"]["Critical"])
            with c_high:
                st.metric("High", analysis["counts"]["High"])
            with c_med:
                st.metric("Medium", analysis["counts"]["Medium"])

            st.markdown("---")

            if analysis["is_clean"]:
                st.balloons()
                st.markdown("""
                <div style="background-color: #DEF7EC; border: 2px solid #31C48D; border-radius: 8px; padding: 14px;">
                    <h4 style="color: #03543F; margin: 0;">✅ CLEAN CONTRACT: ZERO KNOWN VULNERABILITIES DETECTED</h4>
                    <p style="color: #03543F; margin: 4px 0 0 0;">This contract implements non-reentrant guards, checks caller permissions correctly, and does not rely on tx.origin or raw block values.</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                for idx, finding in enumerate(analysis["findings"], 1):
                    sev = finding["severity"]
                    badge_class = "badge-critical" if sev == "Critical" else "badge-high"
                    
                    with st.expander(f"⚠️ {finding['id']}: {finding['name']} ({sev}) — Line {finding['line_number']}", expanded=True):
                        st.markdown(f"<span class='{badge_class}'>Severity: {sev}</span>", unsafe_allow_html=True)
                        st.markdown(f"**Vulnerable Line `{finding['line_number']}`:**")
                        st.code(finding["code_snippet"], language="solidity")
                        st.markdown(f"**Impact:** {finding['description']}")
                        st.markdown(f"**💡 Recommended Fix:** {finding['remediation']}")

                # Download report
                rep_md = auditor.generate_report_markdown(sample_key if sample_key != "-- Choose a Contract --" else "CustomContract.sol", analysis)
                st.download_button(
                    label="📥 Download Security Audit Report (.md)",
                    data=rep_md,
                    file_name="SolidGuard_Audit_Report.md",
                    mime="text/markdown"
                )
        else:
            st.info("👈 Select a sample vulnerable contract or paste Solidity code, then click 'Run Comprehensive Security Audit'.")

# ================= TAB 2: KNOWLEDGE BASE =================
with tabs[1]:
    st.subheader("📚 SWC (Smart Contract Weakness Classification) Knowledge Base")
    st.markdown("SolidGuard utilizes a curated vector knowledge base of known blockchain exploits to semantically audit code.")

    kb = auditor.knowledge_base
    for swc_id, data in kb.items():
        with st.expander(f"{swc_id}: {data['name']} [{data['severity']}]"):
            st.write(f"**Description:** {data['description']}")
            st.write(f"**Pattern Trigger:** `{', '.join(data['patterns'])}`")
            st.info(f"**Standard Remediation:** {data['remediation']}")

# ================= TAB 3: CODE DIFF =================
with tabs[2]:
    st.subheader("⚖️ Before vs. After: Vulnerable vs. Hardened Implementation")
    
    col_vuln, col_fixed = st.columns(2)
    with col_vuln:
        st.markdown("#### ❌ Vulnerable (DAO Reentrancy)")
        st.code("""function withdrawAll() public {
    uint256 balance = balances[msg.sender];
    require(balance > 0);

    // 1. External call happens FIRST
    (bool success, ) = msg.sender.call{value: balance}("");
    require(success);

    // 2. State updated TOO LATE!
    balances[msg.sender] = 0; 
}""", language="solidity")
        st.caption("Attacker recursively re-invokes withdrawAll() before line 9 executes, draining contract.")

    with col_fixed:
        st.markdown("#### ✅ Hardened (Checks-Effects-Interactions + nonReentrant)")
        st.code("""function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient");

    // 1. EFFECTS: State updated BEFORE external call
    balances[msg.sender] -= amount;

    // 2. INTERACTIONS: Low-level call executed safely
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}""", language="solidity")
        st.caption("State variable updated immediately; nonReentrant lock prevents re-entry.")

# ================= TAB 4: ARCHITECTURE =================
with tabs[3]:
    st.subheader("🏗️ SolidGuard System Architecture")
    st.markdown("""
    ```
    [ Solidity Source (.sol) ]
              │
              ├──► [ Regex / AST Tokenizer ] ───────► [ Line & Caller Identification ]
              │                                                     │
              └──► [ RAG Knowledge Base (SWC DB) ] ──► [ Semantic Pattern Matching ]
                                                                    │
                                                                    ▼
                                                    [ Composite Security Auditor ]
                                                                    │
                                            ┌───────────────────────┴───────────────────────┐
                                            ▼                                               ▼
                                [ Security Score (0-100) ]                     [ Remediation Code Diffs ]
    ```
    ### Why this matters for Datopic:
    Datopic regularly conducts smart contract audits and builds dApps for Ethereum and Polygon. Demonstrating tools that automate vulnerability discovery and gas optimization highlights immediate practical capability.
    """)
