# LinnyTool

Linux Security Hardening, Auditing & Grading Tool.

The Linux counterpart to [WinnyTool](https://github.com/AES256Afro/WinnyTool). An all-in-one security platform that installs dependencies, scans for vulnerabilities, hardens your system with backup/restore, and grades your security posture from A+ to F.

## Features

- **Security Grading** — Weighted A+ through F scoring across 7 categories
- **OpenSCAP Integration** — CIS/DISA-STIG compliance scanning and remediation
- **Lynis Integration** — Security auditing with hardening index
- **3-Tier Hardening** — Basic, Moderate, Aggressive profiles with cumulative checks
- **Backup & Restore** — Timestamped config backups with manifest before every change
- **CVE Scanning** — Package-level CVEs, kernel CVEs, NVD/CISA KEV feeds
- **Network Auditing** — Open ports, firewall rules, SSH config, DNS
- **Scan History** — SQLite-backed trend tracking over time
- **HTML Reports** — Styled dark-theme reports with severity badges
- **Multi-Distro** — Debian/Ubuntu, RHEL/Fedora/CentOS, Arch, SUSE
- **Terminal TUI** — Curses-based interactive interface
- **Optional GUI** — Tkinter desktop application (install with `--install-gui`)

## Quick Start

```bash
# Interactive TUI mode
sudo python3 linnytool.py

# Install all security tool dependencies
sudo python3 linnytool.py --install-deps

# Full security scan with grade
sudo python3 linnytool.py --scan

# Apply basic hardening (with automatic backup)
sudo python3 linnytool.py --harden basic

# Dry run — see what would change without applying
sudo python3 linnytool.py --harden moderate --dry-run

# Restore from latest backup
sudo python3 linnytool.py --restore

# Generate HTML report
sudo python3 linnytool.py --report

# Launch GUI
sudo python3 linnytool.py --gui
```

## Hardening Tiers

| Tier | Checks | Scope |
|------|--------|-------|
| Basic | ~10 | SSH hardening, firewall, password policy, auto updates, disable USB storage |
| Moderate | ~10 | + sysctl hardening, auditd, AppArmor/SELinux enforce, AIDE, core dumps |
| Aggressive | ~10 | + disable uncommon filesystems/protocols, GRUB password, login banners |

Tiers are cumulative: Moderate includes all Basic checks, Aggressive includes all.

## Requirements

- Python 3.10+
- Root privileges (sudo)
- Supported distro: Debian/Ubuntu, RHEL/Fedora/CentOS/Rocky/Alma, Arch/Manjaro, openSUSE/SLES

## License

MIT
