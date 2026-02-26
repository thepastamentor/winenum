# WinEnum

Quick and dirty Windows/AD enumeration tool built for HTB and CTF boxes. Point it at an IP, optionally give it creds, and it'll rip through all the common services, grab what it can, and try to crack anything it finds.

## What It Does

- **Port scan** — hits all the common Windows ports (SMB, LDAP, Kerberos, WinRM, RDP, MSSQL, DNS, HTTP, etc.)
- **Domain discovery** — auto-detects the domain name from SMB/LDAP if you don't provide one
- **Service enumeration** — runs everything concurrently:
  - **SMB** — tests auth, enumerates shares, spiders for interesting files (configs, scripts, certs, databases, etc.)
  - **LDAP** — tests anonymous bind, runs `ldapdomaindump` with creds
  - **Kerberos** — detects the service for later attacks
  - **WinRM/RDP/MSSQL** — tests creds, checks for admin access
  - **DNS** — attempts zone transfers
  - **HTTP** — grabs server headers
- **RID brute** — enumerates domain users via RID cycling (tries guest → anonymous → NULL if no creds)
- **AS-REP roasting** — finds users without pre-auth, also tests any users found during RID brute
- **Kerberoasting** — requests TGS tickets for service accounts
- **BloodHound collection** — tries RustHound first (with ADCS), falls back to bloodhound-python
- **Auto-cracking** — dumps all hashes to a single file and runs hashcat against `rockyou.txt` in the background while other tasks are still running

If you provide credentials, it skips all the NULL/guest/anonymous junk and goes straight to authenticated enumeration. No point wasting time testing anonymous access when you already have a valid login.

## Dependencies

Needs the usual pentest toolkit on your path:
- `nmap`
- `netexec` (or `crackmapexec`)
- `smbclient`
- `ldapsearch`
- `impacket` (`impacket-GetNPUsers`, `impacket-GetUserSPNs`)
- `rusthound` and/or `bloodhound-python`
- `hashcat`
- `ldapdomaindump`

Most of this comes pre-installed on Kali/Parrot.

## Usage

```bash
# No creds - just see what's open and what allows anonymous access
python3 winenum.py 10.10.10.100

# With creds - skips anonymous tests, goes straight to auth
python3 winenum.py 10.10.10.100 -u svc_backup -p 'Password123' -d MEGACORP.LOCAL

# Pass the hash
python3 winenum.py 10.10.10.100 -u administrator -H aad3b435b51404ee:31d6cfe0d16ae931 -d MEGACORP.LOCAL

# Custom output dir and more threads
python3 winenum.py 10.10.10.100 -u user -p pass -d CORP -o ./loot -T 8

# Export to JSON
python3 winenum.py 10.10.10.100 -u user -p pass --json results.json
```

## Options

```
positional arguments:
  target                Target IP address

options:
  -u, --username        Username for authentication
  -p, --password        Password for authentication
  -d, --domain          Domain name (auto-discovered if not provided)
  -H, --hash            NTLM hash (LM:NT or just NT)
  -t, --timeout         Command timeout in seconds (default: 15)
  -T, --threads         Number of concurrent threads (default: 5)
  -o, --output          Output directory (default: ./winenum)
  -v, --verbose         Verbose output
  --json FILE           Export results to JSON
```

## Output

Everything gets saved to `./winenum/` by default:

```
winenum/
├── domain_users.txt        # Users found via RID brute
├── hashes                  # All collected hashes (AS-REP + kerberoast)
├── asrep_hashes.txt        # AS-REP hashes (hashcat -m 18200)
├── kerberoast_hashes.txt   # Kerberoast hashes (hashcat -m 13100)
├── cracked.txt             # Cracked passwords
├── zone_transfer.txt       # DNS zone transfer results
├── ldapdump/               # ldapdomaindump HTML output
└── bloodhound/             # BloodHound collection ZIP
```

## How It Runs

Everything runs concurrently in a thread pool — service enumeration, RID brute, kerberoasting, AS-REP roasting, and BloodHound collection all fire at the same time. A background thread watches for hashes and kicks off hashcat as soon as anything lands, so cracking starts while other tasks are still running.

You'll see live progress as tasks complete:

```
[*] Launching 12 tasks concurrently...
[+] [1/12] http ✓
[+] [2/12] rdp ✓
[+] [3/12] kerberos ✓
[+] [4/12] winrm ✓
[★] Found 2 Kerberoastable service account(s)!
[+] [5/12] kerberoast ✓
[*] Cracking Kerberoast hashes (mode 13100)...
[+] [6/12] smb ✓
[+] [7/12] mssql ✓
[★] CRACKED: svc_sql:Summer2024!
...
```

## Disclaimer

Built for authorised security testing and CTF challenges only. Don't be stupid with it.
This has been built for commands/tools as I use them and if your applicaton/wordlist/etc placement is different those functions will not work and are not my problem.
