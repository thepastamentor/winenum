from winenum.core.result import ServiceResult
from winenum.core.target import Target
from winenum.core.runner import run_command

def enum_winrm(target: Target, open_ports: dict, output_dir: str, progress_id=None, progress_ui=None) -> ServiceResult:
    """Enumerate WinRM service"""
    result = ServiceResult(service='winrm', port=5985)
    
    if 5985 not in open_ports and 5986 not in open_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]WinRM: Port closed[/dim]", completed=100)
        return result
    
    result.open = True
    result.port = 5985 if 5985 in open_ports else 5986
    
    if target.has_creds():
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]WinRM: Testing authentication...[/yellow]")
        cmd = ['netexec', 'winrm', target.ip]
        cmd.extend(target.netexec_auth())
        
        code, stdout, stderr = run_command(cmd)
        
        if '[+]' in stdout:
            if 'Pwn3d!' in stdout:
                if progress_ui:
                    progress_ui.console.print("[magenta bold][★][/magenta bold] WinRM ACCESS - Can get shell!")
                result.details['can_psremote'] = True
            else:
                if progress_ui:
                    progress_ui.console.print("[green][+][/green] WinRM auth works (may need local admin)")
            result.cred_access = True
            
    if progress_ui:
        progress_ui.update(progress_id, description="[green]WinRM: Complete ✓[/green]", completed=100)
        
    return result
