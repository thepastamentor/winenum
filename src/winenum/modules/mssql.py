from winenum.core.result import ServiceResult
from winenum.core.target import Target
from winenum.core.runner import run_command

def enum_mssql(target: Target, open_ports: dict, output_dir: str, progress_id=None, progress_ui=None) -> ServiceResult:
    """Enumerate MSSQL service"""
    result = ServiceResult(service='mssql', port=1433)
    
    if 1433 not in open_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]MSSQL: Port closed[/dim]", completed=100)
        return result
    
    result.open = True
    
    auth_success = False
    auth_cmd = None  # Store the working auth command for xp_cmdshell test
    
    if target.has_creds():
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]MSSQL: Testing domain auth...[/yellow]")
        
        # Test domain auth
        cmd = ['netexec', 'mssql', target.ip]
        cmd.extend(target.netexec_auth())
        
        code, stdout, stderr = run_command(cmd)
        
        if '[+]' in stdout:
            if 'Pwn3d!' in stdout or 'admin' in stdout.lower():
                if progress_ui:
                    progress_ui.console.print("[magenta bold][★][/magenta bold] MSSQL ADMIN access (domain auth)!")
                result.details['is_admin'] = True
            else:
                if progress_ui:
                    progress_ui.console.print("[green][+][/green] MSSQL domain auth successful")
            result.cred_access = True
            auth_success = True
            auth_cmd = cmd[:]
        
        # Also test local auth
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]MSSQL: Testing local auth...[/yellow]")
            
        cmd_local = ['netexec', 'mssql', target.ip, '--local-auth']
        cmd_local.extend(target.netexec_auth())
        
        code, stdout, stderr = run_command(cmd_local)
        
        if '[+]' in stdout:
            if 'Pwn3d!' in stdout or 'admin' in stdout.lower():
                if progress_ui:
                    progress_ui.console.print("[magenta bold][★][/magenta bold] MSSQL ADMIN access (local auth)!")
                result.details['is_admin'] = True
                result.details['local_auth'] = True
            else:
                if progress_ui:
                    progress_ui.console.print("[green][+][/green] MSSQL local auth successful")
                result.details['local_auth'] = True
            result.cred_access = True
            if not auth_success:
                auth_cmd = cmd_local[:]
                auth_success = True
    else:
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]MSSQL: Testing default credentials...[/yellow]")
            
        default_creds = [('sa', ''), ('sa', 'sa'), ('sa', 'password')]
        
        for user, passwd in default_creds:
            cmd = ['netexec', 'mssql', target.ip, '-u', user, '-p', passwd]
            code, stdout, stderr = run_command(cmd, timeout=5)
            
            if '[+]' in stdout:
                if progress_ui:
                    progress_ui.console.print(f"[magenta bold][★][/magenta bold] MSSQL Default creds work: {user}:{passwd}")
                result.details['default_creds'] = f"{user}:{passwd}"
                result.anonymous_access = True
                auth_cmd = cmd[:]
                auth_success = True
                break
    
    # Test xp_cmdshell if any auth worked
    if auth_success and auth_cmd:
        if progress_ui:
            progress_ui.update(progress_id, description="[yellow]MSSQL: Testing xp_cmdshell...[/yellow]")
            
        xp_cmd = auth_cmd + ['-x', 'whoami']
        code, stdout, stderr = run_command(xp_cmd, timeout=15)
        
        if code == 0 and stdout.strip() and '[+]' in stdout:
            if progress_ui:
                progress_ui.console.print("[magenta bold][★][/magenta bold] MSSQL xp_cmdshell is ENABLED!")
            result.details['xp_cmdshell'] = True
            # Extract the whoami output
            for line in stdout.split('\n'):
                line = line.strip()
                if '\\' in line and '[' not in line:
                    result.details['xp_cmdshell_user'] = line
                    if progress_ui:
                        progress_ui.console.print(f"  [green][+][/green] Running as: {line}")
                    break
        else:
            result.details['xp_cmdshell'] = False
            
    if progress_ui:
        progress_ui.update(progress_id, description="[green]MSSQL: Complete ✓[/green]", completed=100)
    
    return result
