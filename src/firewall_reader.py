import subprocess
import json
import time
from tqdm import tqdm

def get_firewall_rules():
    """Retrieves rules with accurate progress tracking and live timing"""
    try:
        ps_script = r"""
        $rules = Get-NetFirewallRule
        $total = $rules.Count
        Write-Output "TOTAL_RULES:$total"
        $rules | ForEach-Object {
            $rule = $_
            $addr = ($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ','
            $port = ($_ | Get-NetFirewallPortFilter).LocalPort -join ','
            
            [PSCustomObject]@{
                Name = $rule.Name
                Enabled = $rule.Enabled.ToString()
                Action = $rule.Action
                Direction = $rule.Direction
                RemoteAddress = $addr
                LocalPort = $port
                Profile = $rule.Profile.ToString()
            } | ConvertTo-Json -Compress
            
            # Write progress to stdout for Python sync
            Write-Output "PROGRESS"
        }
        """

        proc = subprocess.Popen(
            ["powershell", "-Command", ps_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )

        # Get total rules from first line
        first_line = proc.stdout.readline().strip()
        total_rules = int(first_line.split(":")[1])
        
        # Initialize progress bar
        start_time = time.time()
        with tqdm(
            total=total_rules,
            desc="Processing rules",
            unit="rule",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [Elapsed: {elapsed}, Remaining: {remaining}]"
        ) as pbar:
            rules = []
            while True:
                line = proc.stdout.readline()
                if not line and proc.poll() is not None:
                    break
                if line.startswith("PROGRESS"):
                    pbar.update(1)
                elif line.strip():
                    try:
                        rules.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        print(f"\nProcessed {len(rules)} rules in {time.time() - start_time:.2f}s")
        return rules
        
    except Exception as e:
        print(f"\nError: {str(e)}")
        return []
