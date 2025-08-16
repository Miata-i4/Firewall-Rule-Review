DEFAULT_RULE_WHITELIST = {
    "RemoteEventLogSvc", "FPS-SMB", "WINRM", "Netlogon",
    "RemoteDesktop", "WSD", "UPnP", "MSMQ", "DCOM"
}

def parse_ports(port_str):
    """Extracts individual ports from complex port strings"""
    ports = set()
    clean_str = str(port_str).strip("{}")
    
    # Handle ranges (5000-5010) and lists (80,443)
    for part in clean_str.split(','):
        if '-' in part:
            start, end = part.split('-', 1)
            ports.update(range(int(start), int(end)+1))
        elif part.isdigit():
            ports.add(int(part))
    return ports

def analyze_rules(rules):
    """Identifies risks with improved data validation"""
    findings = {
        "unnecessary_open_ports": [],
        "permissive_rules": [],
        "disabled_rules": []
    }
    risky_ports = {80, 445, 3389, 23}

    for rule in rules:
        # Skip default Windows rules
        if any(key in rule.get("Name", "") for key in DEFAULT_RULE_WHITELIST):
            continue

        # Check disabled rules
        if rule.get("Enabled", "").lower() == "false":
            findings["disabled_rules"].append(rule)
            continue

        # Port analysis
        detected_ports = parse_ports(rule.get("LocalPort", ""))
        if detected_ports & risky_ports:
            findings["unnecessary_open_ports"].append(rule)

        # Permissive rules check
        remote_ips = str(rule.get("RemoteAddress", "")).split(',')
        if (
            rule.get("Action") == 2 and 
            "Any" in remote_ips and
            rule.get("Direction") == "Inbound" and
            "Public" in rule.get("Profile", "")
        ):
            findings["permissive_rules"].append(rule)

    return findings