"""Dependency installer for security tools.

Distro-aware package installation for OpenSCAP, Lynis, AIDE, auditd,
fail2ban, rkhunter, chkrootkit, ClamAV, and firewall tools.
"""

import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Optional

from core import run_command, logger
from core.distro_detect import DistroProfile, DistroFamily, PkgManager


@dataclass
class Package:
    """Cross-distro package definition."""
    canonical: str      # Canonical tool name
    apt: str            # Debian/Ubuntu package
    dnf: str            # RHEL/Fedora package
    pacman: str         # Arch package
    zypper: str         # SUSE package
    required: bool = True
    description: str = ""


# Master package table
PACKAGES: list[Package] = [
    Package("openscap-scanner", "openscap-scanner", "openscap-scanner", "openscap", "openscap-utils",
            description="OpenSCAP security compliance scanner"),
    Package("scap-security-guide", "ssg-debderived", "scap-security-guide", "scap-security-guide", "scap-security-guide",
            description="SCAP Security Guide content (CIS/STIG profiles)"),
    Package("openscap-utils", "openscap-utils", "openscap-utils", "", "openscap-utils",
            description="OpenSCAP utilities (oscap CLI)"),
    Package("lynis", "lynis", "lynis", "lynis", "lynis",
            description="Security auditing and hardening tool"),
    Package("aide", "aide", "aide", "aide", "aide",
            description="Advanced Intrusion Detection Environment"),
    Package("auditd", "auditd", "audit", "audit", "audit",
            description="Linux audit framework"),
    Package("fail2ban", "fail2ban", "fail2ban", "fail2ban", "fail2ban",
            description="Brute-force attack prevention"),
    Package("rkhunter", "rkhunter", "rkhunter", "rkhunter", "rkhunter",
            description="Rootkit detection"),
    Package("chkrootkit", "chkrootkit", "chkrootkit", "chkrootkit", "chkrootkit",
            description="Rootkit detection (secondary scanner)"),
    Package("clamav", "clamav", "clamav", "clamav", "clamav",
            description="Malware/virus scanner"),
    Package("ufw", "ufw", "", "", "",
            description="Uncomplicated Firewall (Debian family)"),
    Package("firewalld", "", "firewalld", "firewalld", "firewalld",
            description="Dynamic firewall manager (RHEL/Arch/SUSE)"),
    Package("net-tools", "net-tools", "net-tools", "net-tools", "net-tools",
            description="Network diagnostic utilities"),
]

GUI_PACKAGES: list[Package] = [
    Package("python3-tk", "python3-tk", "python3-tkinter", "tk", "python3-tk",
            required=False, description="Python tkinter GUI library"),
    Package("scap-workbench", "scap-workbench", "scap-workbench", "scap-workbench", "scap-workbench",
            required=False, description="OpenSCAP graphical workbench"),
]


def _get_pkg_name(pkg: Package, profile: DistroProfile) -> str:
    """Get the distro-specific package name."""
    mapping = {
        PkgManager.APT: pkg.apt,
        PkgManager.DNF: pkg.dnf,
        PkgManager.PACMAN: pkg.pacman,
        PkgManager.ZYPPER: pkg.zypper,
    }
    return mapping.get(profile.pkg_manager, "")


def _update_repos(profile: DistroProfile) -> bool:
    """Update package repository metadata."""
    cmds = {
        PkgManager.APT: ["apt-get", "update", "-qq"],
        PkgManager.DNF: ["dnf", "check-update", "-q"],
        PkgManager.PACMAN: ["pacman", "-Sy", "--noconfirm"],
        PkgManager.ZYPPER: ["zypper", "--non-interactive", "refresh"],
    }
    cmd = cmds.get(profile.pkg_manager)
    if cmd is None:
        return False

    logger.info("Updating package repositories...")
    result = run_command(cmd, timeout=600)
    # dnf check-update returns 100 if updates available (not an error)
    if profile.pkg_manager == PkgManager.DNF:
        return result.returncode in (0, 100)
    return result.returncode == 0


def _install_cmd(profile: DistroProfile) -> list[str]:
    """Get the base install command for the distro."""
    cmds = {
        PkgManager.APT: ["apt-get", "install", "-y", "-qq"],
        PkgManager.DNF: ["dnf", "install", "-y", "-q"],
        PkgManager.PACMAN: ["pacman", "-S", "--noconfirm", "--needed"],
        PkgManager.ZYPPER: ["zypper", "--non-interactive", "install"],
    }
    return cmds.get(profile.pkg_manager, [])


def install_package(pkg_name: str, profile: DistroProfile) -> bool:
    """Install a single package using the distro's package manager."""
    if not pkg_name:
        return False

    base_cmd = _install_cmd(profile)
    if not base_cmd:
        logger.error("No install command for package manager: %s", profile.pkg_manager)
        return False

    cmd = base_cmd + [pkg_name]
    logger.info("Installing: %s", pkg_name)

    try:
        result = run_command(cmd, timeout=900)
    except subprocess.TimeoutExpired:
        logger.warning("Install timed out for %s (may still be running in background)", pkg_name)
        # Check if it actually installed despite the timeout (post-install hooks can be slow)
        if _is_installed(pkg_name, profile):
            logger.info("Package %s installed successfully (post-install hook was slow)", pkg_name)
            return True
        return False

    if result.returncode == 0:
        logger.info("Installed: %s", pkg_name)
        return True
    else:
        logger.error("Failed to install %s: %s", pkg_name, result.stderr.strip()[:200])
        return False


def check_installed(profile: DistroProfile) -> dict[str, bool]:
    """Check which packages from the master list are already installed.

    Returns:
        Dict mapping canonical package name to installed status.
    """
    results = {}
    for pkg in PACKAGES:
        pkg_name = _get_pkg_name(pkg, profile)
        if not pkg_name:
            results[pkg.canonical] = False
            continue
        results[pkg.canonical] = _is_installed(pkg_name, profile)
    return results


def _is_installed(pkg_name: str, profile: DistroProfile) -> bool:
    """Check if a specific package is installed."""
    cmds = {
        PkgManager.APT: ["dpkg", "-s", pkg_name],
        PkgManager.DNF: ["rpm", "-q", pkg_name],
        PkgManager.PACMAN: ["pacman", "-Qi", pkg_name],
        PkgManager.ZYPPER: ["rpm", "-q", pkg_name],
    }
    cmd = cmds.get(profile.pkg_manager)
    if cmd is None:
        return False

    try:
        result = run_command(cmd, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


def install_all(
    profile: DistroProfile,
    callback: Optional[Callable[[str, str, bool], None]] = None,
    include_optional: bool = False,
) -> dict[str, bool]:
    """Install all required security tool packages.

    Args:
        profile: Detected distro profile.
        callback: Progress callback(canonical_name, display_msg, success).
        include_optional: Also install GUI packages.

    Returns:
        Dict mapping canonical name to installation success.
    """
    packages = list(PACKAGES)
    if include_optional:
        packages.extend(GUI_PACKAGES)

    # Update repos first
    _update_repos(profile)

    results = {}
    for pkg in packages:
        pkg_name = _get_pkg_name(pkg, profile)

        if not pkg_name:
            msg = f"Not available on {profile.family.value}"
            logger.info("Skipping %s: %s", pkg.canonical, msg)
            if callback:
                callback(pkg.canonical, msg, False)
            results[pkg.canonical] = False
            continue

        # Check if already installed
        if _is_installed(pkg_name, profile):
            msg = "Already installed"
            logger.info("%s: %s", pkg.canonical, msg)
            if callback:
                callback(pkg.canonical, msg, True)
            results[pkg.canonical] = True
            continue

        # Install
        success = install_package(pkg_name, profile)
        msg = "Installed" if success else "Failed"
        if callback:
            callback(pkg.canonical, msg, success)
        results[pkg.canonical] = success

    return results


def install_gui_deps(profile: DistroProfile) -> dict[str, bool]:
    """Install optional GUI dependencies (tkinter, scap-workbench)."""
    _update_repos(profile)
    results = {}
    for pkg in GUI_PACKAGES:
        pkg_name = _get_pkg_name(pkg, profile)
        if not pkg_name:
            results[pkg.canonical] = False
            continue
        if _is_installed(pkg_name, profile):
            results[pkg.canonical] = True
            continue
        results[pkg.canonical] = install_package(pkg_name, profile)
    return results
