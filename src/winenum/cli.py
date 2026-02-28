import argparse
import sys
import os
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress, SpinnerColumn, TextColumn

from winenum.core.target import Target
from winenum.core.console import print_banner, print_status, print_header, console
from winenum.core.result import ServiceResult
from winenum.core.runner import run_command

# Import modules
from winenum.modules.smb import enum_smb, rid_brute
from winenum.modules.ldap import enum_ldap
from winenum.modules.mssql import enum_mssql
from winenum.modules.winrm import enum_winrm
from winenum.modules.rdp import enum_rdp
from winenum.modules.dns import enum_dns
from winenum.modules.http import enum_http
from winenum.modules.kerberos import enum_kerberos, asrep_roast, kerberoast, generate_krb5_conf
from winenum.modules.bloodhound import collect_bloodhound
from winenum.modules.certipy import enum_certipy
from winenum.modules.hashcat import crack_hashes

VERSION = "0.1.0"

SERVICES_INFO = {
    'smb': {'ports': [445, 139], 'name': 'SMB'},
    'ldap': {'ports': [389, 636, 3268, 3269], 'name': 'LDAP'},
    'kerberos': {'ports': [88], 'name': 'Kerberos'},
    'winrm': {'ports': [5985, 5986], 'name': 'WinRM'},
    'rdp': {'ports': [3389], 'name': 'RDP'},
    'mssql': {'ports': [1433], 'name': 'MSSQL'},
    'rpc': {'ports': [135], 'name': 'RPC/MSRPC'},
    'dns': {'ports': [53], 'name': 'DNS'},
    'ftp': {'ports': [21], 'name': 'FTP'},
    'ssh': {'ports': [22], 'name': 'SSH'},
    'http': {'ports': [80, 8080, 8000, 8443], 'name': 'HTTP'},
    'https': {'ports': [443], 'name': 'HTTPS'},
}

class Orchestrator:
    def __init__(self, target: Target, output_dir: str, threads: int = 5, verbose: bool = False, bh_config: dict = None):
        self.target = target
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'winenum')
        self.threads = threads
        self.verbose = verbose
        self.bh_config = bh_config
        self.results: dict[str, ServiceResult] = {}
        self.domain_users = []
        self.open_ports = {}
        os.makedirs(self.output_dir, exist_ok=True)
        
    def scan_ports(self):
        """Initial port scan logic transferred from monolithic file"""
        print_header("PORT SCAN")
        all_ports = set()
        for svc in SERVICES_INFO.values():
            all_ports.update(svc['ports'])
        
        ports_str = ','.join(map(str, sorted(all_ports)))
        
        print_status(f"Scanning {self.target.ip} for common Windows ports...")
        
        cmd = ['nmap', '-Pn', '-sT', '--open', '-T4', '-p', ports_str, self.target.ip]
        code, stdout, stderr = run_command(cmd, timeout=60)
        
        if code == 0:
            import re
            for line in stdout.split('\n'):
                match = re.search(r'(\d+)/tcp\s+open', line)
                if match:
                    port = int(match.group(1))
                    self.open_ports[port] = True
                    print_status(f"Port {port}/tcp is open", "success")
        else:
            print_status("nmap failed, using netcat fallback...", "warning")
            for port in sorted(all_ports):
                cmd = ['nc', '-zv', '-w', '2', self.target.ip, str(port)]
                code, _, _ = run_command(cmd, timeout=5)
                if code == 0:
                    self.open_ports[port] = True
                    print_status(f"Port {port}/tcp is open", "success")
                    
        if not self.open_ports:
            print_status("No open ports found (host may be down or filtered)", "warning")

    def discover_domain(self):
        """Auto-discover domain name logic"""
        if self.target.domain:
            print_status(f"Domain provided: {self.target.domain}", "info")
            return
            
        print_header("DOMAIN DISCOVERY")
        
        if 445 in self.open_ports:
            cmd = ['netexec', 'smb', self.target.ip]
            code, stdout, stderr = run_command(cmd)
            import re
            domain_match = re.search(r'\(domain:([^\)]+)\)', stdout)
            if domain_match:
                self.target.domain = domain_match.group(1)
                print_status(f"Discovered domain: {self.target.domain}", "finding")
                return
                
        if 389 in self.open_ports:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{self.target.ip}', '-s', 'base', 'namingContexts']
            code, stdout, stderr = run_command(cmd)
            if code == 0:
                import re
                dc_match = re.search(r'DC=([^,]+),DC=([^,\s]+)', stdout)
                if dc_match:
                    self.target.domain = f"{dc_match.group(1)}.{dc_match.group(2)}"
                    print_status(f"Discovered domain from LDAP: {self.target.domain}", "finding")
                    return
                    
        print_status("Could not auto-discover domain. Use -d to specify.", "warning")

    def run_concurrent(self):
        enumerate_tasks = [
            ('smb', enum_smb),
            ('ldap', enum_ldap),
            ('mssql', enum_mssql),
            ('winrm', enum_winrm),
            ('rdp', enum_rdp),
            ('dns', enum_dns),
            ('http', enum_http),
            ('kerberos', enum_kerberos),
            ('certipy', enum_certipy)
        ]

        print_header("CONCURRENT ENUMERATION")
        
        # Phase 1: Base Enumeration
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=False
        ) as progress:
            
            futures_map = {}
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Add RID brute
                if 445 in self.open_ports:
                    rid_task = progress.add_task(f"[cyan]RID Brute: Waiting...", total=None)
                    fut = executor.submit(rid_brute, self.target, self.open_ports, self.output_dir, rid_task, progress)
                    futures_map[fut] = 'rid_brute'

                # Add standard services
                for name, func in enumerate_tasks:
                    task_id = progress.add_task(f"[cyan]{name.upper()}: Waiting...", total=None)
                    fut = executor.submit(func, self.target, self.open_ports, self.output_dir, task_id, progress)
                    futures_map[fut] = name
                    
                for future in as_completed(futures_map):
                    name = futures_map[future]
                    try:
                        res = future.result()
                        if isinstance(res, ServiceResult):
                            self.results[name] = res
                        elif name == 'rid_brute':
                            self.domain_users = res
                    except Exception as e:
                        progress.console.print(f"[red][-][/red] {name.upper()} Exception: {e}")

        # Phase 2: Post-Enumeration Attacks (Requires Domain/Users extracted from Phase 1)
        print_header("POST-ENUMERATION RECON & ATTACKS")
        attack_tasks = []
        
        if self.target.domain:
            attack_tasks.append(('asrep', asrep_roast, {'domain_users': self.domain_users}))
            
        if self.target.has_creds() and self.target.domain:
            attack_tasks.append(('kerberoast', kerberoast, {}))
            attack_tasks.append(('bloodhound', collect_bloodhound, {'bh_config': self.bh_config}))
            
        if attack_tasks:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
                transient=False
            ) as progress:
                futures_map = {}
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    for name, func, kwargs in attack_tasks:
                        task_id = progress.add_task(f"[cyan]{name.upper()}: Waiting...", total=None)
                        fut = executor.submit(func, self.target, self.open_ports, self.output_dir, **kwargs, progress_id=task_id, progress_ui=progress)
                        futures_map[fut] = name
                        
                    for future in as_completed(futures_map):
                        name = futures_map[future]
                        try:
                            self.results[name] = future.result()
                        except Exception as e:
                            progress.console.print(f"[red][-][/red] {name.upper()} Exception: {e}")
                            
        crack_hashes(self.output_dir, self.verbose)

    def print_summary(self):
        print_header("ENUMERATION SUMMARY")
        
        console.print(f"\n[bold]Target:[/bold] {self.target.ip}")
        if self.target.domain:
            console.print(f"[bold]Domain:[/bold] {self.target.domain}")
        if self.target.has_creds():
            console.print(f"[bold]Credentials:[/bold] {self.target.cred_string()}")
        console.print(f"[bold]Output:[/bold] {self.output_dir}")
        
        console.print(f"\n[bold cyan]Open Services:[/bold cyan]")
        for name, result in self.results.items():
            if result.open:
                status_parts = []
                if result.anonymous_access:
                    status_parts.append("[green]ANON[/green]")
                if result.guest_access:
                    status_parts.append("[yellow]GUEST[/yellow]")
                if result.cred_access:
                    status_parts.append("[magenta]AUTH[/magenta]")
                
                status = f" [{', '.join(status_parts)}]" if status_parts else ""
                svc_name = SERVICES_INFO.get(name, {}).get('name', name.upper())
                console.print(f"  • {svc_name:15} (port {result.port}){status}")
        
        findings = []
        if self.domain_users:
            findings.append(f"USERS: {len(self.domain_users)} domain users enumerated")
            
        for name, result in self.results.items():
            if name in ['smb', 'ldap', 'rpc'] and result.anonymous_access:
                findings.append(f"{name.upper()}: Anonymous/NULL access available")
            if result.guest_access:
                findings.append(f"{name.upper()}: Guest access available")
            if result.details.get('admin_access'):
                findings.append(f"{name.upper()}: ADMIN ACCESS!")
            if result.details.get('can_psremote'):
                findings.append(f"WINRM: Can get remote shell")
            if result.details.get('signing_required') == False:
                findings.append(f"SMB: Signing not required - relay possible")
            if result.details.get('zone_transfer'):
                findings.append(f"DNS: Zone transfer available")
            if result.details.get('default_creds'):
                findings.append(f"MSSQL: Default creds: {result.details['default_creds']}")
            if result.details.get('nla_required') == False:
                findings.append(f"RDP: NLA not required - check BlueKeep")
            if result.details.get('asrep_hashes'):
                findings.append(f"AS-REP: {len(result.details['asrep_hashes'])} roastable user(s)")
            if result.details.get('kerberoast_hashes'):
                findings.append(f"KERBEROAST: {len(result.details['kerberoast_hashes'])} service account(s)")
            if result.details.get('bloodhound_zip') or result.details.get('bloodhound_ce_zip'):
                findings.append(f"BLOODHOUND: Data collected")
            if result.details.get('adcs_collected'):
                findings.append(f"ADCS: Certificate data collected")
            if result.details.get('vulnerable_templates'):
                findings.append(f"CERTIPY: Vulnerable templates: {', '.join(result.details['vulnerable_templates'])}")
            if result.details.get('xp_cmdshell'):
                user = result.details.get('xp_cmdshell_user', 'unknown')
                findings.append(f"MSSQL: xp_cmdshell ENABLED (running as {user})")
            if result.details.get('local_auth'):
                findings.append(f"MSSQL: Local auth works")
            if result.details.get('ldapdump_dir'):
                findings.append(f"LDAP: Domain dumped to {result.details['ldapdump_dir']}")
                
        for auth_type in ['null', 'guest', 'cred']:
            shares_key = f'shares_{auth_type}'
            smb_result = self.results.get('smb', ServiceResult('smb', 445))
            if shares_key in smb_result.details:
                for share in smb_result.details[shares_key]:
                    if share.get('files'):
                        findings.append(f"SMB: Interesting files found in {share['name']}")
                        break
        
        if findings:
            console.print(f"\n[bold magenta]Key Findings:[/bold magenta]")
            for f in findings:
                console.print(f"  ★ {f}")
        
        console.print(f"\n[bold yellow]Collected Data Files:[/bold yellow]")
        for file in os.listdir(self.output_dir):
            if not file.startswith('.'):
                console.print(f"  → {file}")
        console.print()

def main():
    parser = argparse.ArgumentParser(
        description=f'WinEnum v{VERSION} - Windows Attack Orchestrator (Rich Edition)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan without credentials
  winenum 10.10.10.100
  
  # Scan with credentials
  winenum 10.10.10.100 -u administrator -p Password123 -d MEGACORP
  
  # Auto-upload to BloodHound CE
  winenum 10.10.10.100 -u root -p root -d MEGACORP --bh-uri http://localhost:8080 --bh-user admin --bh-pass Admin123!
        """
    )
    
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-d', '--domain', help='Domain name (auto-discovered if not provided)')
    parser.add_argument('-H', '--hash', help='NTLM hash (LM:NT or just NT)')
    parser.add_argument('-T', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('-o', '--output', help='Output directory (default: ./winenum)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # New BloodHound API Arguments
    parser.add_argument('--bh-uri', help='BloodHound CE URI (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--bh-user', help='BloodHound CE Username')
    parser.add_argument('--bh-pass', help='BloodHound CE Password')
    
    args = parser.parse_args()
    
    if args.password and args.hash:
        parser.error("Cannot specify both password and hash")
        
    bh_config = None
    if args.bh_uri and args.bh_user and args.bh_pass:
        bh_config = {'uri': args.bh_uri, 'user': args.bh_user, 'pass': args.bh_pass}
    elif args.bh_uri or args.bh_user or args.bh_pass:
         parser.error("Must specify all --bh-uri, --bh-user, and --bh-pass to upload to BloodHound CE")
    
    target = Target(
        ip=args.target,
        username=args.username,
        password=args.password,
        domain=args.domain,
        hash=args.hash
    )
    
    print_banner()
    start_time = time.time()
    
    orchestrator = Orchestrator(target, args.output, args.threads, args.verbose, bh_config)
    
    try:
        orchestrator.scan_ports()
        if not orchestrator.open_ports:
            sys.exit(1)
        
        orchestrator.discover_domain()
        
        # Generate krb5.conf if Kerberos available
        if 88 in orchestrator.open_ports and target.has_creds() and target.domain:
            generate_krb5_conf(target, orchestrator.open_ports, orchestrator.output_dir)
            
        orchestrator.run_concurrent()
        
        elapsed = time.time() - start_time
        orchestrator.print_summary()
        print_status(f"Enumeration completed in {elapsed:.1f} seconds", "success")
        
    except KeyboardInterrupt:
        console.print(f"\n[bold yellow][!] Interrupted by user[/bold yellow]")
        sys.exit(1)

if __name__ == '__main__':
    main()
