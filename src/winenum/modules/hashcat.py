import os
from winenum.core.target import Target
from winenum.core.runner import run_command
from winenum.core.utils import save_to_file
from winenum.core.console import print_header, print_status

def crack_hashes(output_dir: str, verbose: bool = False):
    """Attempt to crack collected hashes with hashcat and rockyou.txt"""
    hashes_file = os.path.join(output_dir, 'hashes')
    wordlist = '/usr/share/wordlists/rockyou.txt'
    cracked_file = os.path.join(output_dir, 'cracked.txt')
    
    if not os.path.exists(hashes_file) or os.path.getsize(hashes_file) == 0:
        print_status("No hashes collected, skipping crack phase", "info")
        return
    
    if not os.path.exists(wordlist):
        print_status(f"Wordlist not found: {wordlist}", "warning")
        return
    
    print_header("HASH CRACKING")
    
    # Hash modes to try: AS-REP (18200) and Kerberoast (13100)
    hash_modes = [
        (18200, 'AS-REP ($krb5asrep)'),
        (13100, 'Kerberoast ($krb5tgs)'),
    ]
    
    all_cracked = []
    
    for mode, description in hash_modes:
        print_status(f"Cracking {description} hashes (mode {mode})...", "info")
        
        cmd = ['hashcat', '-m', str(mode), hashes_file, wordlist,
               '--force', '--quiet', '-o', cracked_file, '--outfile-format', '2',
               '--runtime', '300']
        
        print_status(f"  Running hashcat (5 min max per mode)...", "info")
        code, stdout, stderr = run_command(cmd, timeout=330)
        
        if code in [0, 1]:  # 0 = cracked, 1 = exhausted
            # Get cracked results with --show
            show_cmd = ['hashcat', '-m', str(mode), hashes_file, '--show', '--quiet']
            code2, show_stdout, _ = run_command(show_cmd, timeout=30)
            
            if show_stdout.strip():
                for line in show_stdout.strip().split('\n'):
                    if line.strip():
                        all_cracked.append(line.strip())
                        print_status(f"  CRACKED: {line.strip()}", "finding")
        elif code == -2:
            print_status("hashcat not found, skipping crack phase", "warning")
            return
        else:
            if verbose:
                print_status(f"hashcat mode {mode} returned code {code}", "info")
    
    if all_cracked:
        print_status(f"Cracked {len(all_cracked)} hash(es)!", "finding")
        # Save all cracked results
        save_to_file(output_dir, 'cracked.txt', '\n'.join(all_cracked) + '\n')
        print_status(f"Cracked hashes saved to {cracked_file}", "success")
    else:
        print_status("No hashes cracked with rockyou.txt", "info")
