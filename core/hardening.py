"""System hardening with 3 progressive tiers.

Each check has a check_func (audit) and apply_func (remediate).
Tiers are cumulative: Moderate includes Basic, Aggressive includes all.
All changes are backed up before applying. Supports --dry-run mode.
"""

import os
import shutil
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from core import run_command, logger
from core.distro_detect import DistroProfile, DistroFamily, PkgManager
from core.backup_manager import create_backup


class Tier(Enum):
    BASIC = "basic"
    MODERATE = "moderate"
    AGGRESSIVE = "aggressive"


_TIER_ORDER = [Tier.BASIC, Tier.MODERATE, Tier.AGGRESSIVE]


@dataclass
class HardeningCheck:
    id: str
    name: str
    description: str
    category: str
    tier: Tier
    severity: str
    check_func: Callable
    apply_func: Callable
    files_modified: list[str]


# ============================================================================
# BASIC TIER CHECKS
# ============================================================================

def _check_ssh_root_login(profile: DistroProfile) -> tuple[bool, str]:
    config = _get_sshd_effective("permitrootlogin")
    if config == "no":
        return True, "PermitRootLogin is disabled"
    return False, f"PermitRootLogin is '{config}' (should be 'no')"


def _apply_ssh_root_login(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    return _apply_sshd_setting("PermitRootLogin", "no", dry_run)


def _check_ssh_password_auth(profile: DistroProfile) -> tuple[bool, str]:
    # Safety: don't fail if no authorized_keys exist
    has_keys = _check_ssh_keys_exist()
    config = _get_sshd_effective("passwordauthentication")
    if config == "no":
        return True, "Password authentication is disabled"
    if not has_keys:
        return True, "Password auth enabled (no SSH keys found, keeping for access safety)"
    return False, f"PasswordAuthentication is '{config}' (should be 'no')"


def _apply_ssh_password_auth(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if not _check_ssh_keys_exist():
        return False, "SKIPPED: No SSH authorized_keys found. Disabling would lock you out."
    return _apply_sshd_setting("PasswordAuthentication", "no", dry_run)


def _check_ssh_max_auth_tries(profile: DistroProfile) -> tuple[bool, str]:
    val = _get_sshd_effective("maxauthtries")
    try:
        if int(val) <= 4:
            return True, f"MaxAuthTries is {val} (OK)"
    except ValueError:
        pass
    return False, f"MaxAuthTries is '{val}' (should be <= 4)"


def _apply_ssh_max_auth_tries(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    return _apply_sshd_setting("MaxAuthTries", "4", dry_run)


def _check_firewall_enabled(profile: DistroProfile) -> tuple[bool, str]:
    if profile.family == DistroFamily.DEBIAN:
        if shutil.which("ufw"):
            r = run_command(["ufw", "status"], timeout=10)
            if "active" in r.stdout.lower() and "inactive" not in r.stdout.lower():
                return True, "UFW firewall is active"
            return False, "UFW firewall is inactive"
    if shutil.which("firewall-cmd"):
        r = run_command(["firewall-cmd", "--state"], timeout=10)
        if r.returncode == 0:
            return True, "firewalld is active"
        return False, "firewalld is inactive"
    return False, "No supported firewall tool found"


def _apply_firewall_enabled(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would enable firewall and allow SSH"
    if profile.family == DistroFamily.DEBIAN and shutil.which("ufw"):
        run_command(["ufw", "allow", "ssh"], timeout=10)
        run_command(["ufw", "--force", "enable"], timeout=10)
        return True, "UFW enabled with SSH allowed"
    if shutil.which("firewall-cmd"):
        run_command(["firewall-cmd", "--permanent", "--add-service=ssh"], timeout=10)
        run_command(["systemctl", "enable", "--now", "firewalld"], timeout=30)
        run_command(["firewall-cmd", "--reload"], timeout=10)
        return True, "firewalld enabled with SSH allowed"
    return False, "No supported firewall tool"


def _check_password_policy(profile: DistroProfile) -> tuple[bool, str]:
    login_defs = Path("/etc/login.defs")
    if not login_defs.exists():
        return False, "/etc/login.defs not found"
    content = login_defs.read_text()
    issues = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("PASS_MAX_DAYS"):
            val = line.split()[-1]
            try:
                if int(val) > 90:
                    issues.append(f"PASS_MAX_DAYS={val} (should be <=90)")
            except ValueError:
                pass
        elif line.startswith("PASS_MIN_LEN"):
            val = line.split()[-1]
            try:
                if int(val) < 12:
                    issues.append(f"PASS_MIN_LEN={val} (should be >=12)")
            except ValueError:
                pass
    if issues:
        return False, "; ".join(issues)
    return True, "Password policy meets requirements"


def _apply_password_policy(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would set PASS_MAX_DAYS=90, PASS_MIN_LEN=12, PASS_WARN_AGE=7"
    path = Path("/etc/login.defs")
    content = path.read_text()
    replacements = {
        "PASS_MAX_DAYS": "90",
        "PASS_MIN_LEN": "12",
        "PASS_WARN_AGE": "7",
    }
    for key, val in replacements.items():
        import re
        content = re.sub(rf"^{key}\s+\d+", f"{key}\t{val}", content, flags=re.MULTILINE)
    path.write_text(content)
    return True, "Password policy updated"


def _check_disable_usb_storage(profile: DistroProfile) -> tuple[bool, str]:
    modprobe = Path("/etc/modprobe.d/linnytool-usb.conf")
    if modprobe.exists() and "install usb-storage /bin/true" in modprobe.read_text():
        return True, "USB storage module is blacklisted"
    # Also check if any blacklist exists
    for f in Path("/etc/modprobe.d").glob("*.conf"):
        try:
            if "install usb-storage /bin/true" in f.read_text():
                return True, f"USB storage blacklisted in {f.name}"
        except PermissionError:
            pass
    return False, "USB storage module is not blacklisted"


def _apply_disable_usb_storage(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would blacklist usb-storage kernel module"
    path = Path("/etc/modprobe.d/linnytool-usb.conf")
    path.write_text("install usb-storage /bin/true\nblacklist usb-storage\n")
    return True, "USB storage module blacklisted"


def _check_auto_updates(profile: DistroProfile) -> tuple[bool, str]:
    if profile.family == DistroFamily.DEBIAN:
        conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        if conf.exists():
            content = conf.read_text()
            if 'Unattended-Upgrade "1"' in content or "Unattended-Upgrade \"1\"" in content:
                return True, "Unattended upgrades enabled"
        return False, "Unattended upgrades not configured"
    if profile.family == DistroFamily.RHEL:
        r = run_command(["systemctl", "is-enabled", "dnf-automatic.timer"], timeout=10)
        if r.returncode == 0:
            return True, "dnf-automatic is enabled"
        return False, "dnf-automatic is not enabled"
    return True, f"Auto-updates check not implemented for {profile.family.value}"


def _apply_auto_updates(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would enable automatic security updates"
    if profile.family == DistroFamily.DEBIAN:
        run_command(["apt-get", "install", "-y", "-qq", "unattended-upgrades"], timeout=120)
        conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        conf.write_text(
            'APT::Periodic::Update-Package-Lists "1";\n'
            'APT::Periodic::Unattended-Upgrade "1";\n'
        )
        return True, "Unattended upgrades enabled"
    if profile.family == DistroFamily.RHEL:
        run_command(["dnf", "install", "-y", "-q", "dnf-automatic"], timeout=120)
        run_command(["systemctl", "enable", "--now", "dnf-automatic.timer"], timeout=30)
        return True, "dnf-automatic enabled"
    return False, "Not implemented for this distro"


def _check_umask(profile: DistroProfile) -> tuple[bool, str]:
    login_defs = Path("/etc/login.defs")
    if login_defs.exists():
        for line in login_defs.read_text().splitlines():
            if line.strip().startswith("UMASK"):
                val = line.split()[-1]
                if val in ("027", "077"):
                    return True, f"UMASK is {val} (restrictive)"
                return False, f"UMASK is {val} (should be 027 or 077)"
    return False, "UMASK not set in /etc/login.defs"


def _apply_umask(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would set UMASK to 027"
    import re
    path = Path("/etc/login.defs")
    content = path.read_text()
    content = re.sub(r"^UMASK\s+\d+", "UMASK\t\t027", content, flags=re.MULTILINE)
    path.write_text(content)
    return True, "UMASK set to 027"


def _check_ssh_empty_passwords(profile: DistroProfile) -> tuple[bool, str]:
    val = _get_sshd_effective("permitemptypasswords")
    if val == "no":
        return True, "Empty passwords are rejected"
    return False, f"PermitEmptyPasswords is '{val}'"


def _apply_ssh_empty_passwords(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    return _apply_sshd_setting("PermitEmptyPasswords", "no", dry_run)


def _check_screen_lock(profile: DistroProfile) -> tuple[bool, str]:
    val = _get_sshd_effective("clientaliveinterval")
    try:
        if 0 < int(val) <= 900:
            return True, f"ClientAliveInterval is {val}s"
    except ValueError:
        pass
    return False, f"ClientAliveInterval is '{val}' (should be 1-900)"


def _apply_screen_lock(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    ok1, msg1 = _apply_sshd_setting("ClientAliveInterval", "300", dry_run)
    ok2, msg2 = _apply_sshd_setting("ClientAliveCountMax", "3", dry_run)
    return ok1 and ok2, f"{msg1}; {msg2}"


# ============================================================================
# MODERATE TIER CHECKS
# ============================================================================

def _check_sysctl_hardening(profile: DistroProfile) -> tuple[bool, str]:
    required = {
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.all.log_martians": "1",
        "net.ipv4.conf.default.accept_redirects": "0",
        "net.ipv6.conf.all.accept_redirects": "0",
        "kernel.randomize_va_space": "2",
        "fs.suid_dumpable": "0",
        "kernel.dmesg_restrict": "1",
        "net.ipv4.icmp_ignore_bogus_error_responses": "1",
        "net.ipv4.conf.all.rp_filter": "1",
    }
    failures = []
    for key, expected in required.items():
        r = run_command(["sysctl", "-n", key], timeout=5)
        actual = r.stdout.strip()
        if actual != expected:
            failures.append(f"{key}={actual} (need {expected})")
    if failures:
        return False, "; ".join(failures[:5]) + (f" (+{len(failures)-5} more)" if len(failures) > 5 else "")
    return True, "All sysctl parameters are hardened"


def _apply_sysctl_hardening(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    settings = [
        "net.ipv4.conf.all.accept_redirects = 0",
        "net.ipv4.conf.default.accept_redirects = 0",
        "net.ipv4.conf.all.send_redirects = 0",
        "net.ipv4.conf.all.log_martians = 1",
        "net.ipv6.conf.all.accept_redirects = 0",
        "net.ipv6.conf.default.accept_redirects = 0",
        "kernel.randomize_va_space = 2",
        "fs.suid_dumpable = 0",
        "kernel.dmesg_restrict = 1",
        "kernel.kptr_restrict = 2",
        "net.ipv4.icmp_ignore_bogus_error_responses = 1",
        "net.ipv4.conf.all.rp_filter = 1",
        "net.ipv4.conf.default.rp_filter = 1",
        "net.ipv4.tcp_syncookies = 1",
    ]
    if dry_run:
        return True, f"Would write {len(settings)} sysctl settings to /etc/sysctl.d/99-linnytool.conf"
    path = Path("/etc/sysctl.d/99-linnytool.conf")
    path.write_text("# LinnyTool sysctl hardening\n" + "\n".join(settings) + "\n")
    run_command(["sysctl", "--system"], timeout=30)
    return True, f"Applied {len(settings)} sysctl settings"


def _check_auditd(profile: DistroProfile) -> tuple[bool, str]:
    if not shutil.which("auditctl"):
        return False, "auditd is not installed"
    r = run_command(["systemctl", "is-active", "auditd"], timeout=10)
    if r.stdout.strip() != "active":
        return False, "auditd is not running"
    rules_dir = Path("/etc/audit/rules.d")
    if rules_dir.exists():
        rules_files = list(rules_dir.glob("*.rules"))
        if not rules_files:
            return False, "auditd running but no audit rules configured"
    return True, "auditd is active with rules"


def _apply_auditd(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    rules = """# LinnyTool audit rules
# Monitor user/group changes
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor authentication
-w /var/log/auth.log -p wa -k auth
-w /var/log/faillog -p wa -k auth
-w /var/log/lastlog -p wa -k auth

# Monitor network config
-w /etc/hosts -p wa -k network
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/sysctl.d/ -p wa -k sysctl

# Monitor kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /sbin/rmmod -p x -k modules

# Monitor cron
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron

# Privilege escalation
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k priv_esc
"""
    if dry_run:
        return True, "Would configure auditd with security rules"
    path = Path("/etc/audit/rules.d/99-linnytool.rules")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rules)
    run_command(["systemctl", "enable", "--now", "auditd"], timeout=30)
    run_command(["augenrules", "--load"], timeout=30)
    return True, "Audit rules configured and loaded"


def _check_mac_enforcing(profile: DistroProfile) -> tuple[bool, str]:
    aa = Path("/sys/module/apparmor/parameters/enabled")
    if aa.exists():
        try:
            if aa.read_text().strip().upper() == "Y":
                return True, "AppArmor is enabled"
            return False, "AppArmor module loaded but not enabled"
        except PermissionError:
            pass
    se = Path("/sys/fs/selinux/enforce")
    if se.exists():
        try:
            if se.read_text().strip() == "1":
                return True, "SELinux is enforcing"
            return False, "SELinux is in permissive mode"
        except PermissionError:
            pass
    return False, "No MAC framework (AppArmor/SELinux) is active"


def _apply_mac_enforcing(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would enable MAC framework enforcement"
    # AppArmor
    if shutil.which("aa-enforce"):
        run_command(["aa-enforce", "/etc/apparmor.d/*"], timeout=30)
        return True, "AppArmor profiles set to enforce"
    # SELinux
    if shutil.which("setenforce"):
        run_command(["setenforce", "1"], timeout=10)
        # Make persistent
        selinux_config = Path("/etc/selinux/config")
        if selinux_config.exists():
            import re
            content = selinux_config.read_text()
            content = re.sub(r"^SELINUX=.*", "SELINUX=enforcing", content, flags=re.MULTILINE)
            selinux_config.write_text(content)
        return True, "SELinux set to enforcing"
    return False, "No MAC tool available"


def _check_core_dumps(profile: DistroProfile) -> tuple[bool, str]:
    r = run_command(["sysctl", "-n", "fs.suid_dumpable"], timeout=5)
    if r.stdout.strip() == "0":
        limits = Path("/etc/security/limits.d/linnytool-coredump.conf")
        if limits.exists():
            return True, "Core dumps are disabled"
    return False, "Core dumps may be enabled"


def _apply_core_dumps(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would disable core dumps"
    Path("/etc/security/limits.d/linnytool-coredump.conf").write_text("* hard core 0\n")
    run_command(["sysctl", "-w", "fs.suid_dumpable=0"], timeout=5)
    return True, "Core dumps disabled"


def _check_restrict_cron(profile: DistroProfile) -> tuple[bool, str]:
    allow = Path("/etc/cron.allow")
    deny = Path("/etc/cron.deny")
    if allow.exists():
        return True, "/etc/cron.allow exists (whitelist mode)"
    if deny.exists() and deny.read_text().strip():
        return True, "/etc/cron.deny has entries"
    return False, "Cron is not restricted (no cron.allow)"


def _apply_restrict_cron(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would create /etc/cron.allow with root only"
    Path("/etc/cron.allow").write_text("root\n")
    os.chmod("/etc/cron.allow", 0o600)
    return True, "Cron restricted to root via /etc/cron.allow"


def _check_aide(profile: DistroProfile) -> tuple[bool, str]:
    if not shutil.which("aide"):
        return False, "AIDE is not installed"
    db = Path("/var/lib/aide/aide.db")
    if not db.exists():
        db = Path("/var/lib/aide/aide.db.gz")
    if not db.exists():
        return False, "AIDE installed but database not initialized"
    return True, "AIDE is installed and database exists"


def _apply_aide(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would initialize AIDE database"
    if not shutil.which("aide"):
        return False, "AIDE not installed"
    r = run_command(["aide", "--init"], timeout=600)
    if r.returncode == 0:
        # Move new database to active
        new_db = Path("/var/lib/aide/aide.db.new")
        active_db = Path("/var/lib/aide/aide.db")
        if new_db.exists():
            shutil.move(str(new_db), str(active_db))
        new_db_gz = Path("/var/lib/aide/aide.db.new.gz")
        active_db_gz = Path("/var/lib/aide/aide.db.gz")
        if new_db_gz.exists():
            shutil.move(str(new_db_gz), str(active_db_gz))
        return True, "AIDE database initialized"
    return False, f"AIDE init failed: {r.stderr.strip()[:100]}"


def _check_shared_memory(profile: DistroProfile) -> tuple[bool, str]:
    fstab = Path("/etc/fstab")
    if fstab.exists():
        for line in fstab.read_text().splitlines():
            if "/dev/shm" in line and "noexec" in line and "nosuid" in line:
                return True, "/dev/shm is mounted with noexec,nosuid"
    return False, "/dev/shm is not hardened in fstab"


def _apply_shared_memory(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would add noexec,nosuid,nodev to /dev/shm mount"
    fstab = Path("/etc/fstab")
    content = fstab.read_text() if fstab.exists() else ""
    shm_line = "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0\n"
    # Check if already has a /dev/shm line
    new_lines = []
    found = False
    for line in content.splitlines():
        if "/dev/shm" in line:
            new_lines.append(shm_line.rstrip())
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(shm_line.rstrip())
    fstab.write_text("\n".join(new_lines) + "\n")
    run_command(["mount", "-o", "remount", "/dev/shm"], timeout=10)
    return True, "/dev/shm hardened with noexec,nosuid,nodev"


def _check_restrict_su(profile: DistroProfile) -> tuple[bool, str]:
    pam_su = Path("/etc/pam.d/su")
    if pam_su.exists():
        for line in pam_su.read_text().splitlines():
            if "pam_wheel.so" in line and not line.strip().startswith("#"):
                return True, "su restricted to wheel/sudo group via pam_wheel"
    return False, "su is not restricted to wheel group"


def _apply_restrict_su(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would enable pam_wheel.so in /etc/pam.d/su"
    pam_su = Path("/etc/pam.d/su")
    if not pam_su.exists():
        return False, "/etc/pam.d/su not found"
    import re
    content = pam_su.read_text()
    content = re.sub(
        r"^#\s*(auth\s+required\s+pam_wheel\.so.*)",
        r"\1",
        content,
        flags=re.MULTILINE,
    )
    pam_su.write_text(content)
    return True, "su restricted to wheel group"


# ============================================================================
# AGGRESSIVE TIER CHECKS
# ============================================================================

def _check_disable_uncommon_fs(profile: DistroProfile) -> tuple[bool, str]:
    fs_modules = ["cramfs", "freevxfs", "hfs", "hfsplus", "squashfs", "udf"]
    missing = []
    for fs in fs_modules:
        found = False
        for f in Path("/etc/modprobe.d").glob("*.conf"):
            try:
                if f"install {fs} /bin/true" in f.read_text():
                    found = True
                    break
            except PermissionError:
                pass
        if not found:
            missing.append(fs)
    if missing:
        return False, f"Not blacklisted: {', '.join(missing)}"
    return True, "All uncommon filesystems are blacklisted"


def _apply_disable_uncommon_fs(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    fs_modules = ["cramfs", "freevxfs", "hfs", "hfsplus", "squashfs", "udf"]
    if dry_run:
        return True, f"Would blacklist {len(fs_modules)} filesystem modules"
    lines = []
    for fs in fs_modules:
        lines.append(f"install {fs} /bin/true")
        lines.append(f"blacklist {fs}")
    Path("/etc/modprobe.d/linnytool-filesystems.conf").write_text("\n".join(lines) + "\n")
    return True, f"Blacklisted {len(fs_modules)} uncommon filesystem modules"


def _check_disable_uncommon_protocols(profile: DistroProfile) -> tuple[bool, str]:
    protocols = ["dccp", "sctp", "rds", "tipc"]
    missing = []
    for proto in protocols:
        found = False
        for f in Path("/etc/modprobe.d").glob("*.conf"):
            try:
                if f"install {proto} /bin/true" in f.read_text():
                    found = True
                    break
            except PermissionError:
                pass
        if not found:
            missing.append(proto)
    if missing:
        return False, f"Not blacklisted: {', '.join(missing)}"
    return True, "All uncommon network protocols are blacklisted"


def _apply_disable_uncommon_protocols(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    protocols = ["dccp", "sctp", "rds", "tipc"]
    if dry_run:
        return True, f"Would blacklist {len(protocols)} network protocol modules"
    lines = []
    for proto in protocols:
        lines.append(f"install {proto} /bin/true")
        lines.append(f"blacklist {proto}")
    Path("/etc/modprobe.d/linnytool-protocols.conf").write_text("\n".join(lines) + "\n")
    return True, f"Blacklisted {len(protocols)} uncommon network protocols"


def _check_login_banner(profile: DistroProfile) -> tuple[bool, str]:
    banner = Path("/etc/issue")
    if banner.exists():
        content = banner.read_text().strip()
        if content and "authorized" in content.lower():
            return True, "Login banner configured with access warning"
    return False, "No login banner configured"


def _apply_login_banner(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    banner_text = (
        "***********************************************\n"
        "* WARNING: Authorized access only.            *\n"
        "* All activity is monitored and logged.        *\n"
        "* Unauthorized access is strictly prohibited.  *\n"
        "***********************************************\n"
    )
    if dry_run:
        return True, "Would set login banner in /etc/issue and /etc/issue.net"
    Path("/etc/issue").write_text(banner_text)
    Path("/etc/issue.net").write_text(banner_text)
    _apply_sshd_setting("Banner", "/etc/issue.net", dry_run=False)
    return True, "Login banner configured"


def _check_disable_automounting(profile: DistroProfile) -> tuple[bool, str]:
    r = run_command(["systemctl", "is-enabled", "autofs"], timeout=10)
    if r.returncode != 0 or "disabled" in r.stdout or "masked" in r.stdout:
        return True, "autofs is disabled/masked"
    return False, "autofs is enabled"


def _apply_disable_automounting(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would disable and mask autofs"
    run_command(["systemctl", "stop", "autofs"], timeout=10)
    run_command(["systemctl", "disable", "autofs"], timeout=10)
    run_command(["systemctl", "mask", "autofs"], timeout=10)
    return True, "autofs disabled and masked"


def _check_ntp_hardening(profile: DistroProfile) -> tuple[bool, str]:
    for svc in ["chronyd", "systemd-timesyncd", "ntpd"]:
        r = run_command(["systemctl", "is-active", svc], timeout=10)
        if r.stdout.strip() == "active":
            return True, f"Time sync active via {svc}"
    return False, "No NTP/time sync service is active"


def _apply_ntp_hardening(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would enable time synchronization service"
    # Prefer chronyd, fall back to systemd-timesyncd
    if shutil.which("chronyd"):
        run_command(["systemctl", "enable", "--now", "chronyd"], timeout=30)
        return True, "chronyd enabled"
    run_command(["systemctl", "enable", "--now", "systemd-timesyncd"], timeout=30)
    return True, "systemd-timesyncd enabled"


def _check_kernel_pointer_restrict(profile: DistroProfile) -> tuple[bool, str]:
    r = run_command(["sysctl", "-n", "kernel.kptr_restrict"], timeout=5)
    if r.stdout.strip() == "2":
        return True, "kernel.kptr_restrict is 2 (fully restricted)"
    return False, f"kernel.kptr_restrict is {r.stdout.strip()} (should be 2)"


def _apply_kernel_pointer_restrict(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would set kernel.kptr_restrict=2"
    run_command(["sysctl", "-w", "kernel.kptr_restrict=2"], timeout=5)
    return True, "kernel.kptr_restrict set to 2"


def _check_disable_wireless(profile: DistroProfile) -> tuple[bool, str]:
    r = run_command(["rfkill", "list", "wifi"], timeout=5)
    if r.returncode != 0:
        return True, "No wireless devices found"
    if "Soft blocked: yes" in r.stdout and "Hard blocked" in r.stdout:
        return True, "Wireless is blocked"
    if not r.stdout.strip():
        return True, "No wireless devices found"
    return False, "Wireless is not disabled"


def _apply_disable_wireless(profile: DistroProfile, dry_run: bool) -> tuple[bool, str]:
    if dry_run:
        return True, "Would soft-block all wireless devices"
    run_command(["rfkill", "block", "wifi"], timeout=10)
    return True, "Wireless devices soft-blocked"


# ============================================================================
# CHECK REGISTRY
# ============================================================================

ALL_CHECKS: list[HardeningCheck] = [
    # === BASIC ===
    HardeningCheck("SSH_ROOT_LOGIN", "Disable SSH Root Login", "Prevent direct root SSH access",
                   "Authentication & Users", Tier.BASIC, "High",
                   _check_ssh_root_login, _apply_ssh_root_login,
                   ["/etc/ssh/sshd_config.d/50-linnytool.conf"]),
    HardeningCheck("FIREWALL", "Enable Firewall", "Activate host firewall with SSH allowed",
                   "Network Security", Tier.BASIC, "High",
                   _check_firewall_enabled, _apply_firewall_enabled, []),
    HardeningCheck("PASSWORD_POLICY", "Password Policy", "Enforce strong password requirements",
                   "Authentication & Users", Tier.BASIC, "Medium",
                   _check_password_policy, _apply_password_policy, ["/etc/login.defs"]),
    HardeningCheck("USB_STORAGE", "Disable USB Storage", "Blacklist USB storage kernel module",
                   "System Hardening", Tier.BASIC, "Medium",
                   _check_disable_usb_storage, _apply_disable_usb_storage,
                   ["/etc/modprobe.d/linnytool-usb.conf"]),
    HardeningCheck("AUTO_UPDATES", "Automatic Updates", "Enable automatic security updates",
                   "System Updates", Tier.BASIC, "High",
                   _check_auto_updates, _apply_auto_updates,
                   ["/etc/apt/apt.conf.d/20auto-upgrades"]),
    HardeningCheck("SSH_PASSWORD_AUTH", "SSH Password Auth", "Disable SSH password authentication",
                   "Authentication & Users", Tier.BASIC, "Medium",
                   _check_ssh_password_auth, _apply_ssh_password_auth,
                   ["/etc/ssh/sshd_config.d/50-linnytool.conf"]),
    HardeningCheck("SSH_MAX_AUTH", "SSH Max Auth Tries", "Limit SSH authentication attempts",
                   "Network Security", Tier.BASIC, "Medium",
                   _check_ssh_max_auth_tries, _apply_ssh_max_auth_tries,
                   ["/etc/ssh/sshd_config.d/50-linnytool.conf"]),
    HardeningCheck("UMASK", "Restrictive UMASK", "Set default file creation mask to 027",
                   "Filesystem & Integrity", Tier.BASIC, "Low",
                   _check_umask, _apply_umask, ["/etc/login.defs"]),
    HardeningCheck("SSH_EMPTY_PASS", "Reject Empty Passwords", "Disallow empty password SSH login",
                   "Authentication & Users", Tier.BASIC, "Critical",
                   _check_ssh_empty_passwords, _apply_ssh_empty_passwords,
                   ["/etc/ssh/sshd_config.d/50-linnytool.conf"]),
    HardeningCheck("SESSION_TIMEOUT", "Session Timeout", "Configure SSH idle session timeout",
                   "Network Security", Tier.BASIC, "Low",
                   _check_screen_lock, _apply_screen_lock,
                   ["/etc/ssh/sshd_config.d/50-linnytool.conf"]),

    # === MODERATE ===
    HardeningCheck("SYSCTL", "Kernel Sysctl Hardening", "Apply secure kernel parameters",
                   "System Hardening", Tier.MODERATE, "High",
                   _check_sysctl_hardening, _apply_sysctl_hardening,
                   ["/etc/sysctl.d/99-linnytool.conf"]),
    HardeningCheck("AUDITD", "Audit Framework", "Configure system call auditing",
                   "System Hardening", Tier.MODERATE, "High",
                   _check_auditd, _apply_auditd,
                   ["/etc/audit/rules.d/99-linnytool.rules"]),
    HardeningCheck("MAC_ENFORCE", "MAC Enforcement", "Enable AppArmor/SELinux enforcement",
                   "Access Control", Tier.MODERATE, "High",
                   _check_mac_enforcing, _apply_mac_enforcing,
                   ["/etc/selinux/config"]),
    HardeningCheck("AIDE", "File Integrity Monitoring", "Initialize AIDE integrity database",
                   "Filesystem & Integrity", Tier.MODERATE, "High",
                   _check_aide, _apply_aide, []),
    HardeningCheck("CORE_DUMPS", "Disable Core Dumps", "Prevent core dump generation",
                   "System Hardening", Tier.MODERATE, "Medium",
                   _check_core_dumps, _apply_core_dumps,
                   ["/etc/security/limits.d/linnytool-coredump.conf"]),
    HardeningCheck("RESTRICT_CRON", "Restrict Cron", "Limit cron access to root",
                   "System Hardening", Tier.MODERATE, "Medium",
                   _check_restrict_cron, _apply_restrict_cron,
                   ["/etc/cron.allow"]),
    HardeningCheck("SHARED_MEMORY", "Secure Shared Memory", "Mount /dev/shm with noexec,nosuid",
                   "System Hardening", Tier.MODERATE, "Medium",
                   _check_shared_memory, _apply_shared_memory, ["/etc/fstab"]),
    HardeningCheck("RESTRICT_SU", "Restrict su", "Limit su command to wheel group",
                   "Authentication & Users", Tier.MODERATE, "Medium",
                   _check_restrict_su, _apply_restrict_su, ["/etc/pam.d/su"]),

    # === AGGRESSIVE ===
    HardeningCheck("UNCOMMON_FS", "Disable Uncommon Filesystems", "Blacklist cramfs, hfs, etc.",
                   "System Hardening", Tier.AGGRESSIVE, "Medium",
                   _check_disable_uncommon_fs, _apply_disable_uncommon_fs,
                   ["/etc/modprobe.d/linnytool-filesystems.conf"]),
    HardeningCheck("UNCOMMON_PROTO", "Disable Uncommon Protocols", "Blacklist DCCP, SCTP, RDS, TIPC",
                   "Network Security", Tier.AGGRESSIVE, "Medium",
                   _check_disable_uncommon_protocols, _apply_disable_uncommon_protocols,
                   ["/etc/modprobe.d/linnytool-protocols.conf"]),
    HardeningCheck("LOGIN_BANNER", "Login Banner", "Configure authorized-access-only warning",
                   "System Hardening", Tier.AGGRESSIVE, "Low",
                   _check_login_banner, _apply_login_banner,
                   ["/etc/issue", "/etc/issue.net"]),
    HardeningCheck("AUTOMOUNTING", "Disable Automounting", "Disable and mask autofs service",
                   "System Hardening", Tier.AGGRESSIVE, "Medium",
                   _check_disable_automounting, _apply_disable_automounting, []),
    HardeningCheck("NTP", "Time Synchronization", "Enable NTP/chrony for accurate time",
                   "System Hardening", Tier.AGGRESSIVE, "Low",
                   _check_ntp_hardening, _apply_ntp_hardening, []),
    HardeningCheck("KPTR_RESTRICT", "Kernel Pointer Restriction", "Fully restrict kernel pointer exposure",
                   "System Hardening", Tier.AGGRESSIVE, "Medium",
                   _check_kernel_pointer_restrict, _apply_kernel_pointer_restrict, []),
    HardeningCheck("WIRELESS", "Disable Wireless", "Soft-block all wireless devices",
                   "Network Security", Tier.AGGRESSIVE, "Low",
                   _check_disable_wireless, _apply_disable_wireless, []),
]


# ============================================================================
# ORCHESTRATION
# ============================================================================

def get_checks_for_tier(tier: Tier) -> list[HardeningCheck]:
    """Return all checks up to and including the specified tier (cumulative)."""
    tier_idx = _TIER_ORDER.index(tier)
    return [c for c in ALL_CHECKS if _TIER_ORDER.index(c.tier) <= tier_idx]


def audit(tier: Tier, profile: DistroProfile) -> list[dict]:
    """Run check_func for all checks in tier without applying changes."""
    checks = get_checks_for_tier(tier)
    results = []
    for check in checks:
        try:
            passes, detail = check.check_func(profile)
            results.append({
                "check_id": check.id,
                "name": check.name,
                "tier": check.tier.value,
                "category": check.category,
                "severity": check.severity,
                "passes": passes,
                "detail": detail,
            })
        except Exception as e:
            logger.error("Check %s failed: %s", check.id, e)
            results.append({
                "check_id": check.id, "name": check.name,
                "tier": check.tier.value, "category": check.category,
                "severity": check.severity, "passes": False,
                "detail": f"Error: {e}",
            })
    return results


def apply(
    tier: Tier,
    profile: DistroProfile,
    dry_run: bool = False,
) -> list[dict]:
    """Run checks and apply fixes for failing ones.

    Always creates a backup before modifying any files.
    """
    checks = get_checks_for_tier(tier)
    results = []

    # Collect all files that may be modified for backup
    if not dry_run:
        all_files = []
        for check in checks:
            all_files.extend(check.files_modified)
        all_files = list(set(f for f in all_files if Path(f).exists()))
        if all_files:
            create_backup(
                all_files,
                reason=f"pre-hardening-{tier.value}",
                distro_name=profile.display_name,
            )

    for check in checks:
        try:
            passes, detail = check.check_func(profile)
            if passes:
                results.append({
                    "check_id": check.id, "name": check.name,
                    "tier": check.tier.value, "category": check.category,
                    "severity": check.severity,
                    "was_passing": True, "action_taken": "none",
                    "success": True, "detail": detail,
                })
            else:
                success, apply_detail = check.apply_func(profile, dry_run)
                results.append({
                    "check_id": check.id, "name": check.name,
                    "tier": check.tier.value, "category": check.category,
                    "severity": check.severity,
                    "was_passing": False,
                    "action_taken": "dry_run" if dry_run else "applied",
                    "success": success,
                    "detail": apply_detail,
                })
        except Exception as e:
            logger.error("Hardening %s failed: %s", check.id, e)
            results.append({
                "check_id": check.id, "name": check.name,
                "tier": check.tier.value, "category": check.category,
                "severity": check.severity,
                "was_passing": False, "action_taken": "error",
                "success": False, "detail": str(e),
            })

    # Restart sshd if any SSH settings were changed
    if not dry_run:
        ssh_checks = [r for r in results if r["check_id"].startswith("SSH_") and r["action_taken"] == "applied"]
        if ssh_checks:
            _restart_sshd()

    return results


def get_findings_as_dicts(audit_results: list[dict]) -> list[dict]:
    """Convert audit results to standard findings format for grading."""
    return [
        {
            "category": r["category"],
            "check_name": r["check_id"],
            "severity": r["severity"],
            "status": "Pass" if r["passes"] else "Fail",
            "description": r["detail"],
            "remediation": "",
        }
        for r in audit_results
    ]


# ============================================================================
# HELPERS
# ============================================================================

def _get_sshd_effective(setting: str) -> str:
    """Get effective SSH server config value."""
    if shutil.which("sshd"):
        r = run_command(["sshd", "-T"], timeout=10)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                parts = line.strip().lower().split(None, 1)
                if len(parts) == 2 and parts[0] == setting.lower():
                    return parts[1]
    # Fallback: parse config files
    for cfg in [Path("/etc/ssh/sshd_config")] + sorted(Path("/etc/ssh/sshd_config.d").glob("*.conf")):
        if cfg.exists():
            try:
                for line in cfg.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2 and parts[0].lower() == setting.lower():
                        return parts[1].lower()
            except PermissionError:
                pass
    return ""


def _apply_sshd_setting(key: str, value: str, dry_run: bool) -> tuple[bool, str]:
    """Write an SSH setting to the LinnyTool drop-in config."""
    if dry_run:
        return True, f"Would set {key} {value}"
    dropin = Path("/etc/ssh/sshd_config.d/50-linnytool.conf")
    dropin.parent.mkdir(parents=True, exist_ok=True)

    # Read existing content or start fresh
    lines = []
    if dropin.exists():
        lines = dropin.read_text().splitlines()

    # Update or add the setting
    updated = False
    new_lines = []
    for line in lines:
        if line.strip().lower().startswith(key.lower()):
            new_lines.append(f"{key} {value}")
            updated = True
        else:
            new_lines.append(line)
    if not updated:
        new_lines.append(f"{key} {value}")

    dropin.write_text("\n".join(new_lines) + "\n")
    return True, f"Set {key} {value} in {dropin}"


def _restart_sshd() -> None:
    """Restart SSH daemon safely."""
    # Validate config first
    if shutil.which("sshd"):
        r = run_command(["sshd", "-t"], timeout=10)
        if r.returncode != 0:
            logger.error("SSH config validation failed: %s", r.stderr.strip())
            return
    run_command(["systemctl", "restart", "sshd"], timeout=30)
    logger.info("SSH daemon restarted")


def _check_ssh_keys_exist() -> bool:
    """Check if any SSH authorized_keys files exist for non-root users."""
    for home in Path("/home").iterdir():
        ak = home / ".ssh" / "authorized_keys"
        if ak.exists() and ak.stat().st_size > 0:
            return True
    # Also check root
    root_ak = Path("/root/.ssh/authorized_keys")
    if root_ak.exists() and root_ak.stat().st_size > 0:
        return True
    return False
