import sys
import os
from pathlib import Path
import streamlit as st

# Add project root to Python path (crucial for module resolution)
project_root = Path(__file__).resolve().parent.parent
sys.path.append(str(project_root))

# Now import your modules
from src.firewall_reader import get_firewall_rules
from src.rule_analyzer import analyze_rules
from src.report_generator import generate_excel_report, print_console_report

# Configure Streamlit page
st.set_page_config(
    page_title="Firewall Auditor",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded"
)

def display_analysis_results(findings):
    """Show interactive results with download option"""
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.subheader("Analysis Summary")
        st.code(print_console_report(findings), language="bash")
    
    with col2:
        st.subheader("Download Report")
        with open("reports/firewall_report.xlsx", "rb") as f:
            st.download_button(
                label="📥 Excel Report",
                data=f,
                file_name="firewall_audit.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                help="Download detailed Excel report"
            )

def main():
    st.title("Firewall Rule Auditor")
    st.markdown("---")
    
    if st.button("🔍 Start Security Audit", type="primary"):
        with st.status("Analyzing firewall configuration...", expanded=True) as status:
            try:
                # Step 1: Collect rules
                st.write("🔄 Collecting firewall rules...")
                rules = get_firewall_rules()
                
                if not rules:
                    st.error("No firewall rules found!")
                    return
                
                # Step 2: Analyze risks
                st.write("🔍 Identifying security risks...")
                findings = analyze_rules(rules)
                
                # Step 3: Generate report
                st.write("📊 Preparing final report...")
                generate_excel_report(findings)
                
                status.update(
                    label="Audit Complete ✅", 
                    state="complete", 
                    expanded=False
                )
                
                display_analysis_results(findings)
                
            except Exception as e:
                st.error(f"Audit Failed: {str(e)}")
                status.update(
                    label="❌ Audit Failed", 
                    state="error",
                    expanded=False
                )

if __name__ == "__main__":
    # Create reports directory if missing
    os.makedirs("reports", exist_ok=True)
    main()