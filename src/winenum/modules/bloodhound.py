import glob
import os
import requests
import urllib3
from winenum.core.result import ServiceResult
from winenum.core.target import Target
from winenum.core.runner import run_command

# Suppress insecure request warnings if using HTTPS without valid certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _upload_to_bloodhound_ce(zip_filename: str, bh_uri: str, bh_user: str, bh_pass: str, progress_ui=None, progress_id=None):
    """Upload zip file securely to BloodHound CE"""
    try:
        if progress_ui:
            progress_ui.update(progress_id, description=f"[yellow]BH CE API: Authenticating to {bh_uri}...[/yellow]")
        
        # 1. Login to get Bearer Token
        login_url = f"{bh_uri.rstrip('/')}/api/v2/login"
        payload = {"login_method": "secret", "username": bh_user, "secret": bh_pass}
        resp = requests.post(login_url, json=payload, verify=False, timeout=10)
        
        if resp.status_code != 200:
            if progress_ui:
                progress_ui.console.print(f"[red][-][/red] BH CE Login failed: {resp.status_code} - {resp.text}")
            return
            
        token = resp.json().get('data', {}).get('session_token')
        if not token:
            if progress_ui:
                progress_ui.console.print("[red][-][/red] No session token returned from BloodHound CE")
            return
            
        # 2. Upload the file payload
        if progress_ui:
            progress_ui.update(progress_id, description=f"[yellow]BH CE API: Uploading {os.path.basename(zip_filename)}...[/yellow]")
            
        upload_url = f"{bh_uri.rstrip('/')}/api/v2/file-upload"
        headers = {"Authorization": f"Bearer {token}"}
        
        with open(zip_filename, 'rb') as f:
            files = {'file': (os.path.basename(zip_filename), f, 'application/zip')}
            up_resp = requests.post(upload_url, headers=headers, files=files, verify=False, timeout=30)
            
            if up_resp.status_code in [200, 201, 202]:
                if progress_ui:
                    progress_ui.console.print("[magenta bold][★][/magenta bold] Successfully uploaded to BloodHound CE API!")
            else:
                if progress_ui:
                    progress_ui.console.print(f"[red][-][/red] Upload failed: {up_resp.text}")
                
    except Exception as e:
        if progress_ui:
            progress_ui.console.print(f"[red][-][/red] Error communicating with BloodHound CE API: {e}")

def _collect_rusthound_ce(target: Target, result: ServiceResult, output_dir: str, 
                          bh_uri: str = None, bh_user: str = None, bh_pass: str = None, 
                          progress_ui=None, progress_id=None) -> bool:
    """Collect using rusthound-ce for BloodHound Community Edition"""
    bh_ce_dir = os.path.join(output_dir, 'bloodhound-ce')
    os.makedirs(bh_ce_dir, exist_ok=True)
    
    if target.hash:
        return False
    
    cmd = ['rusthound-ce',
           '-d', target.domain,
           '-i', target.ip,
           '-u', f'{target.username}@{target.domain}',
           '-p', target.password,
           '-o', bh_ce_dir,
           '-z']
    
    if progress_ui:
        progress_ui.update(progress_id, description="[yellow]BloodHound: Running RustHound-CE...[/yellow]")
        
    code, stdout, stderr = run_command(cmd, timeout=180)
    
    if code == 0:
        zip_files = glob.glob(f'{bh_ce_dir}/*.zip')
        if zip_files:
            zip_path = zip_files[0]
            if progress_ui:
                progress_ui.console.print("[magenta bold][★][/magenta bold] BloodHound CE data collected!")
                progress_ui.console.print(f"  [green][+][/green] {zip_path}")
            result.details['bloodhound_ce_zip'] = zip_path
            
            # --- Auto Upload to BloodHound CE ---
            if bh_uri and bh_user and bh_pass:
                _upload_to_bloodhound_ce(zip_path, bh_uri, bh_user, bh_pass, progress_ui, progress_id)
                
            return True
            
    if code == -2 and progress_ui:
        progress_ui.console.print("[yellow][!][/yellow] rusthound-ce not found, skipping CE collection")
    return False

def _collect_rusthound(target: Target, result: ServiceResult, output_dir: str, progress_ui=None, progress_id=None) -> bool:
    """Collect using rusthound"""
    bh_dir = os.path.join(output_dir, 'bloodhound')
    os.makedirs(bh_dir, exist_ok=True)
    
    if target.hash:
        return False
    
    cmd = ['rusthound',
           '-d', target.domain,
           '-i', target.ip,
           '-u', f'{target.username}@{target.domain}',
           '-p', target.password,
           '-o', bh_dir,
           '-z',
           '--adcs']
    
    if progress_ui:
        progress_ui.update(progress_id, description="[yellow]BloodHound: Running RustHound (+ADCS)...[/yellow]")
        
    code, stdout, stderr = run_command(cmd, timeout=180)
    
    if code == 0:
        zip_files = glob.glob(f'{bh_dir}/*.zip')
        if zip_files:
            if progress_ui:
                progress_ui.console.print("[magenta bold][★][/magenta bold] BloodHound data collected!")
                progress_ui.console.print(f"  [green][+][/green] {zip_files[0]}")
            result.details['bloodhound_zip'] = zip_files[0]
            
            if 'adcs' in stdout.lower() or 'certificate' in stdout.lower():
                result.details['adcs_collected'] = True
                if progress_ui:
                    progress_ui.console.print("  [green][+][/green] ADCS data included")
            return True
    return False

def _collect_bloodhound_py(target: Target, result: ServiceResult, output_dir: str, progress_ui=None, progress_id=None) -> bool:
    """Collect using bloodhound-python"""
    bh_dir = os.path.join(output_dir, 'bloodhound')
    os.makedirs(bh_dir, exist_ok=True)
    
    cmd = ['bloodhound-python',
           '-d', target.domain,
           '-u', target.username,
           '-dc', target.ip,
           '-ns', target.ip,
           '-c', 'All',
           '--zip']
    
    if target.hash:
        cmd.extend(['--hashes', f':{target.hash}'])
    else:
        cmd.extend(['-p', target.password])
    
    if progress_ui:
        progress_ui.update(progress_id, description="[yellow]BloodHound: Running bloodhound-python...[/yellow]")
        
    original_dir = os.getcwd()
    os.chdir(bh_dir)
    code, stdout, stderr = run_command(cmd, timeout=300)
    os.chdir(original_dir)
    
    if code == 0:
        zip_files = glob.glob(f'{bh_dir}/*.zip')
        if zip_files:
            if progress_ui:
                progress_ui.console.print("[magenta bold][★][/magenta bold] BloodHound data collected (bloodhound.py)!")
                progress_ui.console.print(f"  [green][+][/green] {zip_files[0]}")
            result.details['bloodhound_zip'] = zip_files[0]
            return True
    return False

def collect_bloodhound(target: Target, open_ports: dict, output_dir: str, 
                       bh_config: dict = None, progress_id=None, progress_ui=None) -> ServiceResult:
    """Collect BloodHound data"""
    result = ServiceResult(service='bloodhound', port=389)
    
    if 389 not in open_ports and 636 not in open_ports:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]BloodHound: LDAP closed[/dim]", completed=100)
        return result
    
    if not target.has_creds() or not target.domain:
        if progress_ui:
            progress_ui.update(progress_id, description="[dim]BloodHound: Needs creds & domain[/dim]", completed=100)
        return result
    
    result.open = True
    
    # Run rusthound (legacy BH) with failover to bloodhound-python
    if _collect_rusthound(target, result, output_dir, progress_ui, progress_id):
        result.cred_access = True
    else:
        if _collect_bloodhound_py(target, result, output_dir, progress_ui, progress_id):
            result.cred_access = True
    
    # Extract API config
    bh_uri = bh_config.get('uri') if bh_config else None
    bh_user = bh_config.get('user') if bh_config else None
    bh_pass = bh_config.get('pass') if bh_config else None

    # Run rusthound-ce (BloodHound CE) 
    _collect_rusthound_ce(target, result, output_dir, bh_uri, bh_user, bh_pass, progress_ui, progress_id)
    
    if progress_ui:
        progress_ui.update(progress_id, description="[green]BloodHound: Complete ✓[/green]", completed=100)
        
    return result
