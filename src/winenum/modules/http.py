import re
from winenum.core.result import ServiceResult
from winenum.core.target import Target
from winenum.core.runner import run_command

def enum_http(target: Target, open_ports: dict, output_dir: str, progress_id=None, progress_ui=None) -> ServiceResult:
    """Enumerate HTTP service"""
    result = ServiceResult(service='http', port=80)
    
    http_ports = [p for p in [80, 8080, 8000, 443, 8443] if p in open_ports]
    if not http_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]HTTP: Port closed[/dim]", completed=100)
        return result
    
    result.open = True
    result.port = http_ports[0]
    
    for port in http_ports:
        scheme = 'https' if port in [443, 8443] else 'http'
        url = f"{scheme}://{target.ip}:{port}"
        
        if progress_ui:
            progress_ui.update(progress_id, description=f"[yellow]HTTP: Checking {url}...[/yellow]")
        
        cmd = ['curl', '-s', '-I', '-k', '-m', '5', url]
        code, stdout, stderr = run_command(cmd)
        
        if code == 0:
            server_match = re.search(r'Server:\s*(.+)', stdout, re.IGNORECASE)
            if server_match:
                result.details[f'server_{port}'] = server_match.group(1).strip()
                if progress_ui:
                    progress_ui.console.print(f"  [blue][*][/blue] HTTP {port} Server: {server_match.group(1).strip()}")
            
            if 'WWW-Authenticate' in stdout:
                if progress_ui:
                    progress_ui.console.print(f"  [yellow][!][/yellow] HTTP {port} requires authentication")
                    
        # Check for PROPFIND (WebDAV)
        if progress_ui:
            progress_ui.update(progress_id, description=f"[yellow]HTTP: Checking WebDAV on {port}...[/yellow]")
        options_cmd = ['curl', '-s', '-I', '-X', 'OPTIONS', '-k', '-m', '5', url]
        code, stdout, stderr = run_command(options_cmd)
        if code == 0 and 'PROPFIND' in stdout:
             if progress_ui:
                progress_ui.console.print(f"  [magenta bold][★][/magenta bold] HTTP {port} has WebDAV enabled (PROPFIND)!")
             result.details[f'webdav_{port}'] = True
             
    if progress_ui:
        progress_ui.update(progress_id, description="[green]HTTP: Complete ✓[/green]", completed=100)
        
    return result
