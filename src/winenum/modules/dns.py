import re
from winenum.core.result import ServiceResult
from winenum.core.target import Target
from winenum.core.runner import run_command
from winenum.core.utils import save_to_file

def enum_dns(target: Target, open_ports: dict, output_dir: str, progress_id=None, progress_ui=None) -> ServiceResult:
    """Enumerate DNS service"""
    result = ServiceResult(service='dns', port=53)
    
    if 53 not in open_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]DNS: Port closed[/dim]", completed=100)
        return result
    
    result.open = True
    
    if target.domain:
        if progress_ui:
            progress_ui.update(progress_id, description=f"[yellow]DNS: Attempting zone transfer for {target.domain}...[/yellow]")
            
        cmd = ['dig', 'axfr', target.domain, f'@{target.ip}']
        code, stdout, stderr = run_command(cmd)
        
        if code == 0 and 'XFR' in stdout and 'Transfer failed' not in stdout:
            if progress_ui:
                progress_ui.console.print("[magenta bold][★][/magenta bold] DNS Zone transfer successful!")
            result.anonymous_access = True
            result.details['zone_transfer'] = True
            
            filepath = save_to_file(output_dir, 'zone_transfer.txt', stdout)
            if progress_ui:
                progress_ui.console.print(f"  [green][+][/green] Saved to {filepath}")
                
    if progress_ui:
        progress_ui.update(progress_id, description="[green]DNS: Complete ✓[/green]", completed=100)
        
    return result
