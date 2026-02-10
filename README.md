# DISCLAMER: This is a personal project script and is still in early stages. Bugs and improper function to be expected. I used Claude Opus 4.5 to assist in formating and module functionality in this project.   

# TODO: Fix the HTML report, iron out the text report, verify accuracy of discovered vulnerablities. 

# Linux Enumeration Script

A comprehensive security enumeration tool for Linux systems that identifies vulnerabilities, misconfigurations, and privilege escalation vectors.

## Features

- **Kernel Vulnerability Detection** - Checks for 12+ critical CVEs (Dirty Pipe, Dirty COW, etc.)
- **Privilege Escalation Checks** - SUID/SGID binaries, sudo misconfigurations, writable files
- **Credential Discovery** - SSH keys, shell history, config files, cloud credentials
- **Network Enumeration** - Open ports, connections, firewall rules
- **Container Detection** - Docker, LXC/LXD, Kubernetes
- **Multiple Output Formats** - Terminal, text file, or HTML report
- **40+ Enumeration Section** - Complete system analysis

## Quick Start

```bash
# Make executable
chmod +x clesV03.sh

# Run with terminal output
./clesV03.sh

# Generate text report
./clesV03.sh --text

# Generate HTML report
./clesV03.sh --html

# Generate both formats
./clesV03.sh --all
```

## Usage

```
./clesV03.sh [OPTIONS]

Options:
  -t, --text          Generate text report
  -h, --html          Generate HTML report
  -a, --all           Generate all report formats
  -o, --output DIR    Output directory (default: ./enum_results)
  -q, --quiet         Suppress terminal output
  --help              Show help message
```

## Examples

```bash
# Basic enumeration with text backup
./clesV03.sh -t

# Professional HTML report for clients
./clesV03.sh -h -o ./client_reports

# Silent mode for automated scanning
./clesV03.sh -a -q -o /var/security/scans

# Search for critical findings
grep "!!!" ./enum_results/*.txt
```

## What It Checks

### System Information
- Operating system and kernel version
- Known kernel vulnerabilities (CVEs)
- System uptime and virtualization

### Security Vulnerabilities
- **Kernel Exploits**: Dirty Pipe, Dirty COW, OverlayFS, eBPF, and more
- **Sudo Vulnerabilities**: Baron Samedit (CVE-2021-3156)
- **Polkit**: PwnKit (CVE-2021-4034)
- **NOPASSWD** sudo entries

### Users & Permissions
- Current user context and groups
- Privileged users (UID 0)
- SUID/SGID binaries
- Writable files in sensitive directories

### Credentials & Secrets
- SSH keys and configurations
- Shell history files
- Cloud credentials (AWS, GCP, Azure)
- Password files and database files
- Git credentials

### Network
- Network interfaces and routing
- Open ports and listening services
- Active connections
- Firewall rules

### Containers & Cloud
- Docker installation and socket access
- LXC/LXD containers
- Kubernetes configuration
- Cloud metadata services

### File System
- Writable directories
- Recently modified files
- Backup and config files
- Temporary directories

### Persistence
- Cron jobs and scheduled tasks
- Systemd services and timers
- Writable service files

## Output Formats

### Terminal Output
Real-time colored output with severity indicators:
- `[!!!]` Critical findings
- `[!]` Warnings
- `[*]` Information
- `[✓]` Success

### Text Report
Plain text file perfect for:
- Searching with grep
- Log ingestion
- Automated analysis
- Documentation

### HTML Report
Professional web-based report with:
- Color-coded severity levels
- Visual statistics dashboard
- Responsive design
- Print-friendly formatting

## Analysis Tips

```bash
# Find all critical issues
grep "\[!!!\]" report.txt

# Extract all CVEs
grep "CVE-" report.txt

# Search for credentials
grep -i "password\|secret\|key\|token" report.txt

# Count vulnerabilities
grep -c "CVE-" report.txt
```

## Detected CVEs

- **CVE-2022-0847** (Dirty Pipe) - Linux 5.8-5.16.10
- **CVE-2021-4034** (PwnKit) - All polkit versions 2009-2022
- **CVE-2021-3493** (OverlayFS) - Linux 4.4-5.11
- **CVE-2021-3156** (Baron Samedit) - sudo 1.8.2-1.8.31p2, 1.9.0-1.9.5p1
- **CVE-2017-16995** (eBPF) - Linux 4.4-4.14.11
- **CVE-2016-5195** (Dirty COW) - Linux 2.6.22-4.8.3
- **CVE-2016-0728** (Keyring) - Linux 3.8-4.4.1
- **CVE-2015-1328** (OverlayFS Ubuntu) - Ubuntu 3.13-3.19
- And more...

## Automated Scanning

```bash
# Add to crontab for daily scans
0 2 * * * /opt/scripts/enum.sh -a -q -o /var/security/daily_scans

# Multi-host scanning
for host in web1 web2 db1; do
    ssh $host "bash -s -- -t -q" < enum.sh > ./reports/${host}.txt
done

# Alert on critical findings
if grep -q "\[!!!\]" report.txt; then
    mail -s "Critical Security Issues" admin@example.com < report.txt
fi
```

## Security Considerations

⚠️ **Reports contain sensitive information:**
- System vulnerabilities
- User credentials (potentially)
- Network topology
- Internal IP addresses
- Service versions

**Always:**
- Protect reports with appropriate permissions (`chmod 600`)
- Delete reports securely when no longer needed (`shred -vfz`)
- Only use on systems you own or have authorization to test

## Use Cases

- **Security Assessments** - Identify vulnerabilities and misconfigurations
- **Penetration Testing** - Privilege escalation enumeration
- **Incident Response** - Collect system evidence
- **Compliance Audits** - Document security posture
- **System Hardening** - Identify areas for improvement
- **Regular Monitoring** - Track changes over time
- **CTF** - Search privilege escalation paths on CTF challenges 

## Requirements

- Linux operating system
- Bash shell
- Standard utilities (find, grep, ps, netstat/ss, etc.)
- Root/sudo access for complete enumeration (optional but recommended)

## Legal Disclaimer

⚠️ **For Authorized Use Only**

This tool is designed for security professionals conducting authorized security assessments. Only use on systems you own or have explicit written permission to test.

Unauthorized access to computer systems is illegal. Use responsibly.

## Resources

- **GTFOBins**: https://gtfobins.github.io/ (SUID exploitation)
- **PEASS-ng**: https://github.com/carlospolop/PEASS-ng (Privilege escalation)
- **HackTricks**: https://book.hacktricks.xyz/ (Pentesting knowledge)

## Version

**Version:** 0.3 Comprehensive Edition  
**Last Updated:** 2026

## License

Use for authorized security assessments only. See disclaimer above.

---

**Happy Enumerating! 🔍**
