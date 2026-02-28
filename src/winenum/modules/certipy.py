import os
import glob
import re
from winenum.core.result import ServiceResult
from winenum.core.target import Target
from winenum.core.runner import run_command

def enum_certipy(target: Target, open_ports: dict, output_dir: str, progress_id=None, progress_ui=None) -> ServiceResult:
    """Enumerate ADCS with certipy-ad"""
    result = ServiceResult(service='certipy', port=389)
    
    if 389 not in open_ports and 636 not in open_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]Certipy: LDAP closed[/dim]", completed=100)
        return result
    
    if not target.has_creds() or not target.domain:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]Certipy: Needs creds & domain[/dim]", completed=100)
        return result
    
    result.open = True
    
    certipy_dir = os.path.join(output_dir, 'certipy')
    os.makedirs(certipy_dir, exist_ok=True)
    
    user_string = f'{target.username}@{target.domain}'
    original_dir = os.getcwd()
    
    if progress_ui:
        progress_ui.update(progress_id, description="[yellow]Certipy: Enumerating ADCS...[/yellow]")
        
    # Try certipy-ad first, then certipy
    for tool in ['certipy-ad', 'certipy']:
        cmd = [tool, 'find',
               '-u', user_string,
               '-dc-ip', target.ip,
               '-vulnerable', '-enabled',
               '-output', 'certipy']
        
        if target.hash:
            cmd.extend(['-hashes', f':{target.hash}'])
        else:
            cmd.extend(['-p', target.password])
        
        os.chdir(certipy_dir)
        code, stdout, stderr = run_command(cmd, timeout=120)
        os.chdir(original_dir)
        
        if code == -2:  # Command not found
            continue
        
        if code == 0:
            result.cred_access = True
            
            # Check for vulnerable templates
            if 'ESC' in stdout:
                vuln_templates = re.findall(r'(ESC\d+)', stdout)
                if vuln_templates:
                    result.details['vulnerable_templates'] = list(set(vuln_templates))
                    if progress_ui:
                        progress_ui.console.print(f"[magenta bold][★][/magenta bold] Vulnerable templates found: {', '.join(set(vuln_templates))}")
            
            # List output files
            cert_files = glob.glob(f'{certipy_dir}/certipy*')
            if cert_files:
                result.details['certipy_output'] = cert_files
                for f in cert_files:
                    if progress_ui:
                        progress_ui.console.print(f"  [green][+][/green] {os.path.basename(f)}")
        
        break  # Don't try fallback if first tool ran
    
    if progress_ui:
        progress_ui.update(progress_id, description="[green]Certipy: Complete ✓[/green]", completed=100)
        
    return result
