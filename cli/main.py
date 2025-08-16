from src.firewall_reader import get_firewall_rules
from src.rule_analyzer import analyze_rules
from src.report_generator import generate_excel_report, print_console_report

def main():
    print("Fetching firewall rules...")
    rules = get_firewall_rules()

    if not rules:
        print("No firewall rules found or PowerShell command failed.")
        return

    print("Analyzing firewall rules...")
    findings = analyze_rules(rules)

    print("Generating report...")
    generate_excel_report(findings)
    print_console_report(findings)

if __name__ == "__main__":
    main()
