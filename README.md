# LinnyTool

**Linux Security Hardening, Auditing & Grading Tool**

The Linux counterpart to [WinnyTool](https://github.com/AES256Afro/WinnyTool). An all-in-one security platform that installs dependencies, scans for vulnerabilities, hardens your system with automatic backup/restore, and grades your security posture from A+ to F.

Built with pure Python 3.10+ and zero external dependencies. Terminal-first with an optional tkinter GUI.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
  - [CLI Commands](#cli-commands)
  - [Interactive TUI](#interactive-tui)
  - [GUI Mode](#gui-mode)
- [Security Grading](#security-grading)
- [Hardening Tiers](#hardening-tiers)
- [Scanning Capabilities](#scanning-capabilities)
  - [OpenSCAP Integration](#openscap-integration)
  - [Lynis Integration](#lynis-integration)
  - [CVE Scanner](#cve-scanner)
  - [Network Auditing](#network-auditing)
- [Backup & Restore](#backup--restore)
- [Reporting](#reporting)
- [Scan History](#scan-history)
- [Multi-Distro Support](#multi-distro-support)
- [Project Structure](#project-structure)
- [Security Resources](#security-resources)
- [Requirements](#requirements)
- [License](#license)

---

## Features

| Feature | Description |
|---------|-------------|
| **Security Grading** | Weighted A+ through F scoring across 7 categories |
| **3-Tier Hardening** | 26 cumulative checks across Basic, Moderate, and Aggressive profiles |
| **OpenSCAP Integration** | CIS/DISA-STIG compliance scanning with auto profile selection |
| **Lynis Integration** | Security auditing with hardening index (0-100) |
| **CVE Scanning** | Package-level CVEs, kernel CVEs, NVD API 2.0, CISA KEV cross-referencing |
| **Network Auditing** | Open ports, firewall rules, SSH configuration, DNS resolver checks |
| **Backup & Restore** | Timestamped config backups with SHA256-verified manifests |
| **Scan History** | SQLite-backed trend tracking over time |
| **HTML Reports** | Styled dark-theme reports with severity badges and grade circles |
| **Terminal TUI** | Curses-based interactive interface with arrow-key navigation |
| **Optional GUI** | Tkinter desktop application mirroring WinnyTool's sidebar layout |
| **Multi-Distro** | Debian/Ubuntu, RHEL/Fedora/CentOS, Arch/Manjaro, openSUSE/SLES |
| **Dry Run Mode** | Preview all changes before applying |
| **Dependency Installer** | Auto-installs 13+ security tools with distro-aware package mapping |
| **SSH Lockout Prevention** | Checks for authorized_keys before disabling password auth |
| **Container Detection** | Detects Docker, LXC, Podman, WSL environments |
| **Drop-in Config Files** | All changes go to separate config files, never edits system defaults |

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/AES256Afro/LinnyTool.git
cd LinnyTool

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

# Launch GUI (requires tkinter)
sudo python3 linnytool.py --gui
```

---

## Installation

LinnyTool is a standalone Python script with no pip dependencies. Just clone and run.

```bash
git clone https://github.com/AES256Afro/LinnyTool.git
cd LinnyTool
sudo python3 linnytool.py --install-deps
```

The `--install-deps` command auto-detects your distro and installs the appropriate packages:

| Tool | Debian/Ubuntu | RHEL/Fedora | Arch | SUSE | Purpose |
|------|--------------|-------------|------|------|---------|
| OpenSCAP | `libopenscap8` | `openscap-scanner` | `openscap` | `openscap-utils` | SCAP compliance scanning |
| SCAP Security Guide | `ssg-debderived` | `scap-security-guide` | `scap-security-guide` | `scap-security-guide` | CIS/STIG profiles |
| OpenSCAP Utils | `openscap-utils` | `openscap-utils` | — | `openscap-utils` | oscap CLI |
| Lynis | `lynis` | `lynis` | `lynis` | `lynis` | Security auditing |
| AIDE | `aide` | `aide` | `aide` | `aide` | File integrity monitoring |
| auditd | `auditd` | `audit` | `audit` | `audit` | System call auditing |
| fail2ban | `fail2ban` | `fail2ban` | `fail2ban` | `fail2ban` | Brute-force prevention |
| rkhunter | `rkhunter` | `rkhunter` | `rkhunter` | `rkhunter` | Rootkit detection |
| chkrootkit | `chkrootkit` | `chkrootkit` | `chkrootkit` | `chkrootkit` | Rootkit detection (secondary) |
| ClamAV | `clamav` | `clamav` | `clamav` | `clamav` | Malware scanning |
| UFW | `ufw` | — | — | — | Firewall (Debian) |
| firewalld | — | `firewalld` | `firewalld` | `firewalld` | Firewall (RHEL/Arch/SUSE) |
| net-tools | `net-tools` | `net-tools` | `net-tools` | `net-tools` | Network diagnostics |

**Optional GUI packages:**
```bash
sudo python3 linnytool.py --install-gui
```
Installs `python3-tk` (tkinter) and `scap-workbench` (OpenSCAP GUI).

---

## Usage

### CLI Commands

```
usage: linnytool [-h] [--scan] [--harden TIER] [--restore [SNAPSHOT]]
                 [--report] [--install-deps] [--install-gui] [--dry-run]
                 [--gui] [--history] [--resources] [--sysinfo] [--version]
                 [--verbose]
```

| Flag | Description | Root Required |
|------|-------------|:---:|
| `--scan` | Run full security scan with grading | Yes |
| `--harden {basic\|moderate\|aggressive}` | Apply hardening tier | Yes |
| `--restore [SNAPSHOT]` | Restore from backup (latest or path) | Yes |
| `--report` | Generate HTML report | Yes |
| `--install-deps` | Install security tool dependencies | Yes |
| `--install-gui` | Install GUI dependencies (tkinter) | Yes |
| `--dry-run` | Preview changes without applying | Yes |
| `--gui` | Launch tkinter GUI | Yes |
| `--history` | Show scan history | No |
| `--resources` | Show security resource links | No |
| `--sysinfo` | Show system information | Yes |
| `--version` | Display version | No |
| `-v, --verbose` | Verbose logging output | No |

### Interactive TUI

Run without arguments to launch the curses-based terminal interface:

```bash
sudo python3 linnytool.py
```

Navigate with arrow keys, select with Enter, quit with Q. The TUI provides access to:

1. **Full Security Scan** — Runs all scanners and produces a grade
2. **Hardening** — Select tier and apply or dry-run
3. **Backup / Restore** — View snapshots and restore
4. **Scan History** — View past scan results and trends
5. **System Information** — Distro, kernel, CPU, RAM, security tools
6. **Install Dependencies** — Install security tool packages
7. **Security Resources** — Curated links to standards and guides

### GUI Mode

```bash
sudo python3 linnytool.py --gui
```

Dark-themed tkinter interface mirroring WinnyTool's layout:
- Sidebar navigation with all modules
- Threaded scan execution (UI stays responsive)
- Scrollable output panels
- One-click hardening with tier selection and dry-run support
- Backup management with restore buttons
- Scan history table
- System info dashboard

Requires tkinter — install with `--install-gui` if not available.

---

## Security Grading

LinnyTool grades your system from **A+ to F** using the same weighted scoring model as WinnyTool.

### Grade Scale

| Grade | Score Range |
|:-----:|:----------:|
| A+ | 97 – 100 |
| A | 93 – 96 |
| A- | 90 – 92 |
| B+ | 87 – 89 |
| B | 83 – 86 |
| B- | 80 – 82 |
| C+ | 77 – 79 |
| C | 73 – 76 |
| C- | 70 – 72 |
| D+ | 67 – 69 |
| D | 63 – 66 |
| D- | 60 – 62 |
| F | 0 – 59 |

### Category Weights

| Category | Weight | What It Measures |
|----------|:------:|-----------------|
| System Updates | 20% | Pending security updates, package freshness |
| CVE Exposure | 20% | Known vulnerabilities in installed packages and kernel |
| System Hardening | 20% | Sysctl settings, auditd, core dumps, filesystem restrictions |
| Network Security | 15% | Firewall status, open ports, SSH config, dangerous services |
| Access Control | 10% | AppArmor/SELinux enforcement status |
| Authentication & Users | 10% | Password policy, SSH auth settings, su restrictions |
| Filesystem & Integrity | 5% | UMASK, AIDE, file permissions |

### Severity Deductions

Each failed check deducts points from its category based on severity:

| Severity | Points Deducted |
|:--------:|:--------------:|
| Critical | -20 |
| High | -15 |
| Medium | -10 |
| Low | -5 |
| Info | 0 |

Categories that have no findings are excluded from the weighted average, so the score only reflects what was actually tested.

---

## Hardening Tiers

Tiers are **cumulative**: Moderate includes all Basic checks, Aggressive includes everything.

### Basic Tier (10 checks)

| Check | Severity | What It Does |
|-------|:--------:|-------------|
| Disable SSH Root Login | High | Sets `PermitRootLogin no` |
| Enable Firewall | High | Activates UFW/firewalld with SSH allowed |
| Password Policy | Medium | Enforces PASS_MAX_DAYS=90, PASS_MIN_LEN=12 |
| Disable USB Storage | Medium | Blacklists `usb-storage` kernel module |
| Automatic Updates | High | Enables unattended-upgrades (Debian) or dnf-automatic (RHEL) |
| SSH Password Auth | Medium | Disables password auth (only if SSH keys exist) |
| SSH Max Auth Tries | Medium | Limits to 4 attempts |
| Restrictive UMASK | Low | Sets default UMASK to 027 |
| Reject Empty Passwords | Critical | Sets `PermitEmptyPasswords no` |
| Session Timeout | Low | Sets SSH ClientAliveInterval=300, CountMax=3 |

### Moderate Tier (+8 checks)

| Check | Severity | What It Does |
|-------|:--------:|-------------|
| Kernel Sysctl Hardening | High | Hardens 14 sysctl parameters (ICMP redirects, SYN cookies, martian logging, ASLR, etc.) |
| Audit Framework | High | Configures auditd with rules for user/group changes, auth, network, kernel modules, privilege escalation |
| MAC Enforcement | High | Enforces AppArmor profiles or sets SELinux to enforcing |
| File Integrity Monitoring | High | Initializes AIDE database |
| Disable Core Dumps | Medium | Sets `fs.suid_dumpable=0` and hard core limit to 0 |
| Restrict Cron | Medium | Creates `/etc/cron.allow` with root only |
| Secure Shared Memory | Medium | Mounts `/dev/shm` with `noexec,nosuid,nodev` |
| Restrict su | Medium | Enables `pam_wheel.so` to limit su to wheel group |

### Aggressive Tier (+7 checks)

| Check | Severity | What It Does |
|-------|:--------:|-------------|
| Disable Uncommon Filesystems | Medium | Blacklists cramfs, freevxfs, hfs, hfsplus, squashfs, udf |
| Disable Uncommon Protocols | Medium | Blacklists DCCP, SCTP, RDS, TIPC kernel modules |
| Login Banner | Low | Configures authorized-access-only warning in `/etc/issue` and `/etc/issue.net` |
| Disable Automounting | Medium | Stops, disables, and masks autofs |
| Time Synchronization | Low | Enables chronyd or systemd-timesyncd |
| Kernel Pointer Restriction | Medium | Sets `kernel.kptr_restrict=2` (fully restricted) |
| Disable Wireless | Low | Soft-blocks all wireless devices via rfkill |

### Safety Features

- **SSH lockout prevention**: Checks for existing `authorized_keys` before disabling password authentication
- **Firewall safety**: Always allows SSH before enabling the firewall
- **SSH config validation**: Runs `sshd -t` to validate config before restarting
- **Drop-in config files**: SSH settings go to `/etc/ssh/sshd_config.d/50-linnytool.conf`, sysctl to `/etc/sysctl.d/99-linnytool.conf` — original system files are never edited
- **Automatic backup**: Every hardening operation creates a timestamped backup first

---

## Scanning Capabilities

### OpenSCAP Integration

Wraps the `oscap` CLI for SCAP compliance scanning:

- Auto-detects the best SCAP content file for your distro
- Auto-selects profile in priority order: CIS Level 1 Server > CIS Level 2 > Standard > STIG
- Parses XCCDF results XML for structured pass/fail/error counts
- Generates HTML compliance report via oscap
- Handles `oscap` exit code 2 (some checks failed) as normal operation

**Supported SCAP content**: Ubuntu 16.04-24.04, Debian 11-12, RHEL 8-10, Fedora, SUSE 12-15, openSUSE, CentOS 8, AlmaLinux 9, Oracle Linux 7-10

### Lynis Integration

Wraps the Lynis security auditor:

- Runs `lynis audit system` with `--no-colors --cronjob` flags
- Parses `/var/log/lynis-report.dat` key-value format
- Extracts hardening index (0-100)
- Maps warnings and suggestions to severity levels (Critical/High/Medium/Low)
- Maps Lynis finding ID prefixes (AUTH, FILE, SSH, NETW, etc.) to LinnyTool grading categories

### CVE Scanner

Multi-source vulnerability scanning:

| Source | Method |
|--------|--------|
| **Distro packages** | `apt-get upgrade -s`, `dnf updateinfo`, `pacman -Qu`, `zypper list-patches` |
| **Kernel CVEs** | Local database with known kernel vulnerabilities and version matching |
| **NVD API 2.0** | Live queries to `services.nvd.nist.gov` for CVE details and CVSS scores |
| **CISA KEV** | Cross-references findings against Known Exploited Vulnerabilities catalog (24h cache) |

Pre-loaded kernel CVEs include CVE-2024-1086 (nf_tables), CVE-2024-6387 (RegreSSHion), CVE-2024-3094 (xz-utils backdoor), CVE-2021-4034 (PwnKit), CVE-2021-3156 (Baron Samedit), and more.

### Network Auditing

Comprehensive network security analysis:

**Port Scanning:**
- Enumerates all listening ports via `ss -tulpn`
- Flags dangerous services exposed on all interfaces:

| Port | Service | Severity |
|:----:|---------|:--------:|
| 23 | Telnet | Critical |
| 512/513/514 | rexec/rlogin/rsh | Critical |
| 21 | FTP | High |
| 69 | TFTP | High |
| 111 | RPCbind | High |
| 135 | MSRPC | High |
| 139/445 | NetBIOS/SMB | High |
| 2049 | NFS | High |
| 3389 | RDP | High |
| 5900 | VNC | High |
| 6000 | X11 | High |

**Firewall Auditing:**
- Detects and checks UFW, firewalld, nftables, or iptables
- Reports active/inactive status and loaded rules

**SSH Configuration Audit:**
- Uses `sshd -T` for effective merged config (handles drop-in directories)
- Checks 11 SSH security settings against secure baselines:
  - PermitRootLogin, PasswordAuthentication, X11Forwarding, MaxAuthTries,
    PermitEmptyPasswords, AllowTcpForwarding, ClientAliveInterval,
    ClientAliveCountMax, LoginGraceTime, Protocol, LogLevel

**DNS Resolver Check:**
- Parses `/etc/resolv.conf` for nameserver entries
- Detects systemd-resolved usage

---

## Backup & Restore

Every hardening operation automatically creates a backup before modifying any files.

### How It Works

1. **Pre-hardening snapshot**: All config files that will be modified are copied to `/var/lib/linnytool/backups/YYYYMMDD_HHMMSS/`
2. **Directory structure preserved**: Files are backed up in their original directory structure
3. **Manifest**: Each backup includes a `manifest.json` with:
   - Original file path
   - SHA256 hash
   - Owner UID/GID
   - File permissions (octal)
   - File size
   - Reason for backup (e.g., "pre-hardening-basic")
4. **Integrity verification**: SHA256 is verified before restoring

### Commands

```bash
# Restore from the latest backup
sudo python3 linnytool.py --restore

# Restore from a specific snapshot
sudo python3 linnytool.py --restore /var/lib/linnytool/backups/20260321_143022

# List backups (in TUI: Backup / Restore menu)
```

---

## Reporting

### HTML Reports

Generated at `~/LinnyTool_Reports/LinnyTool_Report_YYYYMMDD_HHMMSS.html`

- Dark gradient theme (#1a1a2e to #0f3460)
- Grade circle with letter grade and color coding
- Per-category score bars
- System information table
- Full findings table with severity badges (Critical=red, High=orange, Medium=yellow, Low=blue)
- Card-based layout with shadow effects
- Responsive design, no external dependencies

### Terminal Reports

ANSI-colored output with:
- Grade display with color coding (green A's, blue B's, yellow C's, red D's/F)
- Category score bars
- Severity-coded findings list
- Pass/fail counts

---

## Scan History

SQLite database at `~/.linnytool/history.db`:

- **WAL journal mode** for safe concurrent access
- **Foreign keys** with cascading deletes
- **Indexed** on timestamp and severity for fast queries
- **Trend tracking**: View score progression over time

Two tables:
- `scans`: timestamp, type, grade, score, duration, distro, kernel, hostname, severity counts
- `findings`: scan_id (FK), category, check_name, severity, status, description, remediation

```bash
# View history
python3 linnytool.py --history
```

---

## Multi-Distro Support

LinnyTool auto-detects your distribution by parsing `/etc/os-release` and maps to the correct package manager, firewall tool, and SCAP content.

### Supported Distributions

| Family | Distributions | Package Manager | Firewall |
|--------|--------------|:---------------:|:--------:|
| **Debian** | Ubuntu, Debian, Linux Mint, Pop!_OS, Kali, Raspbian, Zorin, elementary | apt | UFW |
| **RHEL** | RHEL, CentOS, Fedora, Rocky, AlmaLinux, Oracle Linux, Amazon Linux | dnf | firewalld |
| **Arch** | Arch Linux, Manjaro, EndeavourOS, Garuda | pacman | firewalld |
| **SUSE** | openSUSE Leap, openSUSE Tumbleweed, SLES, SLED | zypper | firewalld |

### Environment Detection

- **Containers**: Docker, LXC, Podman, Kubernetes
- **WSL**: Windows Subsystem for Linux
- **Desktop vs Server**: Detects DISPLAY/WAYLAND_DISPLAY, X11/Wayland sessions, display managers
- **Init system**: systemd, sysvinit, OpenRC, Upstart

---

## Project Structure

```
LinnyTool/
├── linnytool.py              # Main entry: CLI argument parsing + curses TUI
├── core/
│   ├── __init__.py           # Shared run_command() subprocess wrapper, version
│   ├── distro_detect.py      # Auto-detect distro, pkg manager, container, SCAP content
│   ├── sysinfo.py            # OS, CPU, RAM, disk, security tools, MAC/firewall status
│   ├── dependency_installer.py # Distro-aware package installation for 13+ security tools
│   ├── backup_manager.py     # Timestamped backups with SHA256 manifest, granular restore
│   ├── hardening.py          # 26 checks across 3 tiers with check/apply functions
│   ├── scanner_openscap.py   # OpenSCAP wrapper: profile selection, XCCDF XML parsing
│   ├── scanner_lynis.py      # Lynis wrapper: audit execution, report.dat parsing
│   ├── cve_scanner.py        # Package CVEs, kernel CVEs, NVD API 2.0, CISA KEV
│   ├── network_audit.py      # Port enumeration, firewall audit, SSH config, DNS check
│   ├── grading.py            # 7 weighted categories, A+ through F, severity deductions
│   ├── history.py            # SQLite scan history with WAL, trend tracking
│   ├── reporter.py           # HTML reports (dark theme) + ANSI terminal output
│   └── resources.py          # Curated security reference links (55+ URLs)
├── gui/
│   ├── __init__.py
│   └── linnytool_gui.py      # Optional tkinter GUI: sidebar nav + dynamic content
├── data/
│   ├── cve_database.json     # Pre-loaded kernel and package CVEs
│   └── settings.json         # User preferences (NVD API key, paths, etc.)
├── README.md
├── LICENSE
└── .gitignore
```

---

## Security Resources

LinnyTool includes a curated collection of 25+ security references across 5 categories:

**Standards & Benchmarks** — CIS Benchmarks, NIST SP 800-123, NIST SP 800-53, DISA STIGs, PCI DSS

**Security Tools** — OpenSCAP, Lynis, AIDE, fail2ban, rkhunter, ClamAV

**Hardening Guides** — Linux Hardening Guide, Ubuntu Security Guide, Red Hat Security Guide, Arch Linux Security Wiki

**Vulnerability Databases** — NVD, CISA KEV, CVE.org, Exploit-DB

**Learning & Training** — Linux Security Expert, OWASP, SANS Institute, Hack The Box

Access via CLI: `python3 linnytool.py --resources`

---

## Requirements

- **Python 3.10+** (ships with all major distros)
- **Root privileges** (sudo) for scanning and hardening
- **Supported distro**: Debian/Ubuntu, RHEL/Fedora/CentOS/Rocky/Alma, Arch/Manjaro, openSUSE/SLES
- **No pip dependencies** — everything uses Python standard library
- **Optional**: tkinter for GUI mode (install with `--install-gui`)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

Built by [AES256Afro](https://github.com/AES256Afro)
