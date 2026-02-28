import glob
import os
import re
from winenum.core.result import ServiceResult
from winenum.core.target import Target
from winenum.core.runner import run_command

def _ldap_anonymous(target: Target, result: ServiceResult, progress_ui=None) -> bool:
    """Test anonymous LDAP access"""
    cmd = ['ldapsearch', '-x', '-H', f'ldap://{target.ip}', 
           '-s', 'base', 'namingContexts']
    code, stdout, stderr = run_command(cmd)
    
    if code == 0 and 'namingContexts' in stdout:
        if progress_ui:
            progress_ui.console.print("[magenta bold][★][/magenta bold] Anonymous LDAP bind allowed!")
        
        contexts = re.findall(r'namingContexts:\s*(.+)', stdout)
        if contexts:
            result.details['naming_contexts'] = contexts
            for ctx in contexts:
                if progress_ui:
                    progress_ui.console.print(f"  [green][+][/green] Naming Context: {ctx}")
                if 'DC=' in ctx:
                    result.details['domain_dn'] = ctx
        return True
    
    return False

def _ldap_authenticated(target: Target, result: ServiceResult, progress_ui=None) -> bool:
    """Test LDAP with credentials"""
    cmd = ['netexec', 'ldap', target.ip]
    cmd.extend(target.netexec_auth())
    
    code, stdout, stderr = run_command(cmd)
    
    if '[+]' in stdout:
        if progress_ui:
            progress_ui.console.print("[green][+][/green] LDAP authentication successful")
        return True
    return False

def _ldap_domain_dump(target: Target, result: ServiceResult, output_dir: str, progress_ui=None):
    """Dump domain info using ldapdomaindump"""
    dump_dir = os.path.join(output_dir, 'ldapdump')
    os.makedirs(dump_dir, exist_ok=True)
    
    if target.domain:
        user = f'{target.domain}\\{target.username}'
    else:
        user = target.username
    
    cmd = ['/usr/bin/ldapdomaindump', '-u', user, '-o', dump_dir]
    
    if target.hash:
        cmd.extend(['-p', target.hash, '--authtype', 'NTLM'])
    else:
        cmd.extend(['-p', target.password])
    
    cmd.append(f'ldap://{target.ip}')
    
    code, stdout, stderr = run_command(cmd, timeout=120)
    
    if code == 0:
        html_files = glob.glob(f'{dump_dir}/*.html')
        if html_files:
            if progress_ui:
                progress_ui.console.print(f"[magenta bold][★][/magenta bold] LDAP dump complete! Files in {dump_dir}")
            result.details['ldapdump_dir'] = dump_dir
            if progress_ui:
                for f in html_files[:5]:
                    progress_ui.console.print(f"  [green][+][/green] {os.path.basename(f)}")
        else:
            if progress_ui:
                progress_ui.console.print("[yellow][!][/yellow] ldapdomaindump completed but no output")
    
def enum_ldap(target: Target, open_ports: dict, output_dir: str, progress_id=None, progress_ui=None) -> ServiceResult:
    """Enumerate LDAP service"""
    result = ServiceResult(service='ldap', port=389)
    
    if 389 not in open_ports and 636 not in open_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]LDAP: Port closed[/dim]", completed=100)
        return result
    
    result.open = True
    
    if target.has_creds():
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]LDAP: Testing authenticated bind...[/yellow]")
        if _ldap_authenticated(target, result, progress_ui):
            result.cred_access = True
            if progress_ui:
                progress_ui.update(progress_id, description="[yellow]LDAP: Dumping domain info...[/yellow]")
            _ldap_domain_dump(target, result, output_dir, progress_ui)
    else:
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]LDAP: Testing anonymous bind...[/yellow]")
        if _ldap_anonymous(target, result, progress_ui):
            result.anonymous_access = True
            
    if progress_ui:
        progress_ui.update(progress_id, description="[green]LDAP: Complete ✓[/green]", completed=100)
    
    return result
