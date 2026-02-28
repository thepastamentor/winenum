import re
from winenum.core.result import ServiceResult
from winenum.core.target import Target
from winenum.core.runner import run_command

def enum_rdp(target: Target, open_ports: dict, output_dir: str, progress_id=None, progress_ui=None) -> ServiceResult:
    """Enumerate RDP service"""
    result = ServiceResult(service='rdp', port=3389)
    
    if 3389 not in open_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]RDP: Port closed[/dim]", completed=100)
        return result
    
    result.open = True
    
    if progress_ui:
        progress_ui.update(progress_id, description="[yellow]RDP: Checking NLA status...[/yellow]")
        
    cmd = ['netexec', 'rdp', target.ip]
    code, stdout, stderr = run_command(cmd)
    
    if 'NLA' in stdout:
        if 'True' in stdout.split('NLA')[1][:20]:
            result.details['nla_required'] = True
        else:
            result.details['nla_required'] = False
            if progress_ui:
                progress_ui.console.print("[magenta bold][★][/magenta bold] RDP NLA NOT required - check BlueKeep!")
    
    if target.has_creds():
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]RDP: Testing authentication...[/yellow]")
        cmd = ['netexec', 'rdp', target.ip]
        cmd.extend(target.netexec_auth())
        
        code, stdout, stderr = run_command(cmd)
        
        if '[+]' in stdout:
            if progress_ui:
                progress_ui.console.print("[magenta bold][★][/magenta bold] RDP authentication successful!")
            result.cred_access = True
            
    if progress_ui:
        progress_ui.update(progress_id, description="[green]RDP: Complete ✓[/green]", completed=100)
        
    return result
