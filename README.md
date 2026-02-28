# WinEnum

A high-speed, concurrent Windows/AD enumeration tool designed specifically for HackTheBox and CTFs. Feed it an IP (and optionally credentials), and it tears straight through all common services concurrently, extracting information, finding vulnerable cert templates, dumping hashes, and immediately throwing them into hashcat. 

Built to eliminate the boring part of AD environments so you can get straight to the blood.

## Features

- **Port scan fallback** — Hits common AD ports (SMB, LDAP, Kerberos, WinRM, RDP, MSSQL, DNS, HTTP). Uses Nmap if installed, falls back to Netcat if nmap fails.
- **Auto-pilot Domain discovery** — Pulls the domain name natively from SMB or LDAP if you forget to provide it.
- **Hosts File Generation** — Automatically generates an `/etc/hosts` compatible file format from SMB enumeration and gives you a one-liner to add it.
- **Concurrent Execution** — Smashes out enumeration with a thread pool. No more waiting 5 minutes for `rusthound` before checking if `netexec` allows a NULL session. It all happens at once.
- **Beautiful UI** — Powered by `rich`, progress bars track every individual service in real-time, popping high-value findings (like `ADMIN ACCESS` or `xp_cmdshell`) directly to the console above the progress bars.
- **Auto-cracking** — Captures AS-REP and Kerberoast hashes simultaneously, concatenates them, and immediately launches `hashcat` to crack them while you read the summary report.
- **BloodHound CE API** — Built-in support to upload `rusthound-ce` zips straight into a running BloodHound CE instance automatically (with an option to wipe the DB prior).

## Dependencies

The script orchestrates the tools you likely already have installed on Kali/Parrot. It expects these commands to be available in your `$PATH`:

- `nmap` & `nc`
- `netexec` (or `crackmapexec`)
- `smbclient`
- `ldapsearch` & `ldapdomaindump`
- `impacket-*` (`impacket-GetNPUsers`, `impacket-GetUserSPNs`)
- `rusthound` / `rusthound-ce`
- `bloodhound-python`
- `certipy-ad` (or just `certipy`)
- `hashcat`
- `dig` & `curl`

## Installation

This is now a proper Python package. You can install it natively so it's globally available anywhere on your system:

```bash
git clone https://github.com/your-repo/winenum.git
cd winenum
pip install .
```

*Don't want to install it globally? You can still run it via `python -m winenum` or run the `winenum.py` wrapper script.*

## Usage

```bash
# Just raw IP - testing for NULL/Anonymous and generating a target map
winenum 10.10.10.100

# Full send - skip anonymous checks and go straight to credentialed enum
winenum 10.10.10.100 -u svc_backup -p 'Password123' -d MEGACORP.LOCAL

# Pass the hash
winenum 10.10.10.100 -u administrator -H aad3b435b51404ee:31d6cfe0d16ae931 -d MEGACORP.LOCAL

# Automatically upload BloodHound data to your local CE instance
winenum 10.10.10.100 -u user -p pass -d CORP --bh-uri http://localhost:8080 --bh-user admin --bh-pass Admin123!

# Wipe the BloodHound CE database before uploading new data
winenum 10.10.10.100 -u user -p pass -d CORP --bh-uri http://localhost:8080 --bh-user admin --bh-pass Admin123! --bh-clear
```

## Options

```
positional arguments:
  target                Target IP address

options:
  -h, --help            show this help message and exit
  -u, --username        Username for authentication
  -p, --password        Password for authentication
  -d, --domain          Domain name (auto-discovered if not provided)
  -H, --hash            NTLM hash (LM:NT or just NT)
  -T, --threads         Number of concurrent threads (default: 5)
  -o, --output          Output directory (default: ./winenum)
  -v, --verbose         Verbose output
  --bh-uri BH_URI       BloodHound CE URI (e.g., http://127.0.0.1:8080)
  --bh-user BH_USER     BloodHound CE Username
  --bh-pass BH_PASS     BloodHound CE Password
  --bh-clear            Clear the BloodHound CE database before uploading data
```

## Caveats and "It Broke" Fixes

Because Windows enumeration relies heavily on how your local pentest box is configured via your `$PATH`, things can behave weirdly if paths don't line up.

- **Hashcat Wordlists**: The script hardcodes the wordlist path to `/usr/share/wordlists/rockyou.txt` (the standard Kali location). If your `rockyou` is somewhere else (like `~/wordlists/rockyou.txt`), the cracking phase will quietly skip itself.
- **Impacket Paths**: Depending on how you installed Impacket, the scripts might be named `GetNPUsers.py` instead of `impacket-GetNPUsers`. This tool calls the `impacket-` prefixed commands. If your tools are missing the prefix, you'll need to alias them or link them in your path.
- **Certipy Executables**: Same as above; the script tries both `certipy-ad find` and `certipy find`. If neither are in your global variables, ADCS enumeration will skip.

If any of these fail, check the `-v` (verbose) flag to see exactly which subprocess command choked and why.

## Disclaimer

Built strictly for authorised security testing, HTB, and CTF environments. Don't throw this at networks you don't own. I wouldn't recommmend it for learning or for OSCP. You can reach me on the HackTheBox discord as VegeLasagne if you have any feedback etc.
