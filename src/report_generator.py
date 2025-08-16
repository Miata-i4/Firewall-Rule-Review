import os
import xlsxwriter
from prettytable import PrettyTable
from colorama import init, Fore, Style

init(autoreset=True)

def generate_excel_report(findings, filename='reports/firewall_report.xlsx'):
    """Generates Excel report with enhanced error handling"""
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        ACTION_MAP = {1: "Block", 2: "Allow"}
        
        with xlsxwriter.Workbook(filename) as workbook:
            worksheet = workbook.add_worksheet('Findings')
            
            headers = ['Issue Type', 'Rule Name', 'Local Port', 
                      'Remote Address', 'Action', 'Profile']
            for col, header in enumerate(headers):
                worksheet.write(0, col, header)
            
            row = 1
            for issue_type, rules in findings.items():
                for rule in rules:
                    safe_data = {
                        'name': str(rule.get("Name", "Unknown")).strip(),
                        'port': str(rule.get("LocalPort", "N/A")).strip("{}"),
                        'remote': str(rule.get("RemoteAddress", "N/A")).strip("{}"),
                        'action': ACTION_MAP.get(rule.get("Action", 0), "Unknown"),
                        'profile': str(rule.get("Profile", "N/A")).strip()
                    }
                    
                    worksheet.write(row, 0, issue_type)
                    worksheet.write(row, 1, safe_data['name'])
                    worksheet.write(row, 2, safe_data['port'])
                    worksheet.write(row, 3, safe_data['remote'])
                    worksheet.write(row, 4, safe_data['action'])
                    worksheet.write(row, 5, safe_data['profile'])
                    row += 1
        
        return True
    except Exception as e:
        print(f"{Fore.RED}Excel generation failed: {str(e)}{Style.RESET_ALL}")
        return False

def print_console_report(findings):
    """Returns formatted analysis summary for both CLI and web"""
    table = PrettyTable()
    table.field_names = [f"{Fore.CYAN}Issue Type{Style.RESET_ALL}", 
                       f"{Fore.CYAN}Count{Style.RESET_ALL}"]
    table.align = "l"

    for issue_type, rules in findings.items():
        table.add_row([
            f"{Fore.YELLOW}{issue_type}{Style.RESET_ALL}", 
            f"{Fore.WHITE}{len(rules)}{Style.RESET_ALL}"
        ])
    
    return f"{Fore.BLUE}=== Firewall Analysis Summary ==={Style.RESET_ALL}\n{table}"