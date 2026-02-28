from winenum.core.console import console
from winenum.core.result import ServiceResult
from winenum.core.target import Target
from winenum.core.runner import run_command
import re

def _smb_get_info(target: Target, result: ServiceResult, progress_ui, progress_id):
    """Get SMB signing and version info"""
    cmd = ['netexec', 'smb', target.ip]
    code, stdout, stderr = run_command(cmd)
    
    for line in stdout.split('\n'):
        if 'signing:' in line.lower():
            if 'False' in line:
                result.details['signing_required'] = False
                if progress_ui:
                    progress_ui.console.print("[magenta bold][★][/magenta bold] SMB Signing: NOT required (relay possible!)")
            else:
                result.details['signing_required'] = True
        
        if 'Windows' in line or 'Samba' in line:
            match = re.search(r'(Windows[^)]+|Samba[^\]]+)', line)
            if match:
                result.details['os_info'] = match.group(1)
                if progress_ui:
                    progress_ui.console.print(f"[blue][*][/blue] OS: {match.group(1)}")

def _smb_spider_share(target: Target, result: ServiceResult, share: dict, user: str, 
                      password: str, auth_type: str, ntlm_hash: str = None, progress_ui=None):
    """Spider a single SMB share for interesting files"""
    share_name = share['name']
    
    # In some versions, netexec allows a 'guest' login but SMB expects '' or 'anonymous'
    smb_user = user
    if auth_type == 'null':
        smb_user = ''
    elif auth_type == 'guest':
        if not user:
            smb_user = 'guest'
            
    if ntlm_hash:
        cmd = ['smbclient', f'//{target.ip}/{share_name}', 
               '-U', f'{smb_user}%', '--pw-nt-hash', ntlm_hash.split(':')[-1],
               '-c', 'recurse ON; ls']
    elif smb_user:
        cmd = ['smbclient', f'//{target.ip}/{share_name}',
               '-U', f'{smb_user}%{password}', '-c', 'recurse ON; ls']
    else:
        cmd = ['smbclient', f'//{target.ip}/{share_name}',
               '-N', '-c', 'recurse ON; ls']
    
    code, stdout, stderr = run_command(cmd, timeout=30)
    
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
            
            # Match smbclient `ls` output format: "  Notice from HR.txt             A     1266  Thu Aug 29 03:31:48 2024"
            # Or: "-rw-rw-rw-  1266  Thu Aug 29 03:31:48 2024 Notice from HR.txt"
            # We skip lines dealing with directories.
            if line.strip() and not line.strip().startswith('d') and not '<DIR>' in line:
                # The safest way to pull the filename is to clean out the size and date blocks
                # We can do this by matching the last column of time: "HH:MM:SS YYYY " and grabbing what's after,
                # OR in standard smbclient, the filename is first, then "A", then size, then date.
                filename = ""
                
                # Check modern smbclient `-c ls` format where filename is at the END:
                # -rw-rw-rw-       1266  Thu Aug 29 03:31:48 2024 Notice from HR.txt
                import re
                
                # Try to match the timestamp `HH:MM:SS YYYY ` and grab what follows it
                file_match = re.search(r'\d{2}:\d{2}:\d{2}\s+\d{4}\s+(.+)$', line)
                if file_match:
                    filename = file_match.group(1).strip()
                else:
                    # Try to match standard smbclient format where filename is at the START:
                    #  Notice from HR.txt                  A     1266  Thu Aug 29 03:31:48 2024
                    parts = line.split('A', 1)
                    if len(parts) > 1 and len(parts[0].strip()) > 0:
                        filename = parts[0].strip()
                
                if not filename:
                    # Fallback string stripping - assume anything with 4 spaces between it and a number is a filename
                    clean_match = re.split(r'\s{2,}', line.strip())
                    if len(clean_match) >= 3:
                        if clean_match[0] == '-' or clean_match[0].startswith('-rw'):
                            filename = clean_match[-1]
                        else:
                            filename = clean_match[0]
                
                if filename and filename not in ['.', '..']:
                    filename_lower = filename.lower()
                    
                    for ext in interesting_extensions:
                        if ext in filename_lower:
                            files_found.append(filename)
                            break
                    else:
                        for name in interesting_names:
                            if name in filename_lower:
                                files_found.append(filename)
                                break
    
    if files_found:
        share['files'] = files_found[:20]
        if progress_ui:
            progress_ui.console.print(f"[magenta bold][★][/magenta bold] Interesting files in {share_name}:")
            for f in files_found[:10]:
                progress_ui.console.print(f"    [green][+][/green] {f}")
            if len(files_found) > 10:
                progress_ui.console.print(f"    [blue][*][/blue] ... and {len(files_found) - 10} more")

def _smb_enum_shares(target: Target, result: ServiceResult, user: str, password: str,
                     auth_type: str, ntlm_hash: str = None, progress_ui=None):
    """Enumerate and spider SMB shares"""
    cmd = ['netexec', 'smb', target.ip, '--shares']
    
    if target.domain and auth_type == 'cred':
        cmd.extend(['-d', target.domain])
    
    cmd.extend(['-u', user])
    
    if ntlm_hash:
        cmd.extend(['-H', ntlm_hash])
    else:
        cmd.extend(['-p', password])
    
    code, stdout, stderr = run_command(cmd, timeout=30)
    
    shares = []
    
    # Flag to start parsing after the header line
    parsing_shares = False
    
    for line in stdout.split('\n'):
        # Netexec prints a separator line before shares: ----- ----------- ------
        if '-----' in line and '-----------' in line:
            parsing_shares = True
            continue
            
        if parsing_shares and line.strip() and target.ip in line:
            # Reconstruct the raw line content after the standard netexec prefix
            # Format: SMB 10.129.231.149 445 CICADA-DC HR READ
            parts = line.split()
            
            # Find the actual share data (starts after the hostname/IP block)
            # Find the index where the IP/Port/Hostname block ends
            try:
                # Find the index of the IP address, then skip Port and Hostname
                ip_idx = parts.index(target.ip)
                share_idx = ip_idx + 3 
                
                if share_idx < len(parts):
                    share_name = parts[share_idx]
                    permissions = "NO ACCESS"
                    
                    # Check the next column for permissions
                    if share_idx + 1 < len(parts):
                        next_part = parts[share_idx + 1]
                        if next_part in ['READ', 'WRITE', 'READ,WRITE']:
                            permissions = next_part
                            
                    if permissions != "NO ACCESS":
                        shares.append({'name': share_name, 'access': permissions, 'files': []})
                        access_color = "[green]" if 'WRITE' in permissions else "[yellow]"
                        if progress_ui:
                            progress_ui.console.print(
                                f"  [green][+][/green] Share: [bold]{share_name}[/bold] "
                                f"[{access_color}{permissions}[/{access_color.strip('[]')}]]"
                            )
            except ValueError:
                pass
    
    result.details[f'shares_{auth_type}'] = shares
    
    interesting_shares = [s for s in shares if s['name'].upper() not in 
                         ['IPC$', 'PRINT$', 'C$', 'ADMIN$']]
    
    if interesting_shares:
        for share in interesting_shares:
            _smb_spider_share(target, result, share, user, password, auth_type, ntlm_hash, progress_ui)


def _smb_test_auth(target: Target, result: ServiceResult, user: str, password: str, 
                   auth_type: str, ntlm_hash: str = None, progress_ui=None) -> bool:
    """Test SMB authentication and enumerate shares"""
    cmd = ['netexec', 'smb', target.ip]
    
    if target.domain and auth_type == 'cred':
        cmd.extend(['-d', target.domain])
    
    cmd.extend(['-u', user])
    
    if ntlm_hash:
        cmd.extend(['-H', ntlm_hash])
    else:
        cmd.extend(['-p', password])
    
    code, stdout, stderr = run_command(cmd)
    
    if '[+]' in stdout:
        is_admin = 'Pwn3d!' in stdout
        if is_admin:
            if progress_ui:
                progress_ui.console.print(f"[magenta bold][★][/magenta bold] ADMIN ACCESS with {auth_type}!")
            result.details['admin_access'] = True
        else:
            if progress_ui:
                icon = "[magenta bold][★][/magenta bold]" if auth_type != 'cred' else "[green][+][/green]"
                progress_ui.console.print(f"{icon} {auth_type.upper()} session allowed!")
        
        _smb_enum_shares(target, result, user, password, auth_type, ntlm_hash, progress_ui)
        return True
    
    return False

def enum_smb(target: Target, open_ports: dict, output_dir: str, progress_id=None, progress_ui=None) -> ServiceResult:
    """Enumerate SMB service"""
    result = ServiceResult(service='smb', port=445)
    
    if 445 not in open_ports and 139 not in open_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]SMB: Port closed[/dim]", completed=100)
        return result
    
    result.open = True
    
    if progress_ui:
        progress_ui.update(progress_id, description="[yellow]SMB: Getting info...[/yellow]")
        
    _smb_get_info(target, result, progress_ui, progress_id)
    
    if target.has_creds():
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]SMB: Testing credentials...[/yellow]")
        if _smb_test_auth(target, result, target.username, 
                               target.password or '', 'cred',
                               target.hash, progress_ui):
            result.cred_access = True
    else:
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]SMB: Testing NULL session...[/yellow]")
        if _smb_test_auth(target, result, '', '', 'null', progress_ui=progress_ui):
            result.anonymous_access = True
        
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]SMB: Testing GUEST session...[/yellow]")
        if _smb_test_auth(target, result, 'guest', '', 'guest', progress_ui=progress_ui):
            result.guest_access = True
    
    if progress_ui:
        progress_ui.update(progress_id, description="[green]SMB: Complete ✓[/green]", completed=100)
        
    return result

def rid_brute(target: Target, open_ports: dict, output_dir: str, progress_id=None, progress_ui=None) -> list:
    """Enumerate users via RID cycling"""
    users = []
    
    if 445 not in open_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]RID Brute: SMB closed[/dim]", completed=100)
        return users
    
    if target.has_creds():
        cmd = ['netexec', 'smb', target.ip, '--rid-brute', '5000']
        cmd.extend(target.netexec_auth())
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]RID Brute: Enumerating with credentials...[/yellow]")
        
        code, stdout, stderr = run_command(cmd, timeout=60)
        
        if code == 0:
            for line in stdout.split('\n'):
                if 'SidTypeUser' in line:
                    user_match = re.search(r'\\([^\s\(]+)', line)
                    if user_match:
                        username = user_match.group(1)
                        if username not in users and username != '':
                            users.append(username)
    
    if not users and not target.has_creds():
        auth_methods = [
            (['-u', 'guest', '-p', ''], 'GUEST'),
            (['-u', 'anonymous', '-p', ''], 'ANONYMOUS'),  
            (['-u', '', '-p', ''], 'NULL'),
        ]
        
        for auth_args, method_name in auth_methods:
            if progress_ui:
                progress_ui.update(progress_id, description=f"[yellow]RID Brute: Testing {method_name} session...[/yellow]")
            
            cmd = ['netexec', 'smb', target.ip, '--rid-brute', '5000'] + auth_args
            code, stdout, stderr = run_command(cmd, timeout=60)
            
            if code == 0 and 'SidTypeUser' in stdout:
                for line in stdout.split('\n'):
                    if 'SidTypeUser' in line:
                        user_match = re.search(r'\\([^\s\(]+)', line)
                        if user_match:
                            username = user_match.group(1)
                            if username not in users and username != '':
                                users.append(username)
                
                if users:
                    if progress_ui:
                        progress_ui.console.print(f"[magenta bold][★][/magenta bold] Success with {method_name} session!")
                    break
    
    if users:
        if progress_ui:
            progress_ui.console.print(f"[magenta bold][★][/magenta bold] Found {len(users)} users via RID brute!")
            for u in users[:10]:
                progress_ui.console.print(f"  [green][+][/green] {u}")
            if len(users) > 10:
                progress_ui.console.print(f"  [blue][*][/blue] ... and {len(users) - 10} more")
    
    if progress_ui:
        desc = f"[green]RID Brute: Complete ({len(users)} users) ✓[/green]" if users else "[dim]RID Brute: No users found[/dim]"
        progress_ui.update(progress_id, description=desc, completed=100)
        
    return users
