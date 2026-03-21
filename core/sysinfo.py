"""System information gathering.

Collects hardware, OS, security tool, and MAC framework status
by parsing /proc, /sys, and running minimal subprocess commands.
"""

import os
import platform
import shutil
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core import run_command, logger
from core.distro_detect import DistroProfile, detect as detect_distro


SECURITY_TOOLS = [
    ("oscap", "OpenSCAP"),
    ("lynis", "Lynis"),
    ("aide", "AIDE"),
    ("auditctl", "auditd"),
    ("fail2ban-client", "fail2ban"),
    ("rkhunter", "rkhunter"),
    ("chkrootkit", "chkrootkit"),
    ("clamscan", "ClamAV"),
    ("ufw", "UFW"),
    ("firewall-cmd", "firewalld"),
    ("nft", "nftables"),
    ("iptables", "iptables"),
    ("aa-status", "AppArmor"),
    ("sestatus", "SELinux"),
]


@dataclass
class DiskInfo:
    mount: str
    device: str
    total_gb: float
    used_gb: float
    free_gb: float
    percent_used: float


@dataclass
class MACStatus:
    framework: str      # "apparmor", "selinux", "none"
    enabled: bool
    mode: str           # "enforce", "complain", "permissive", "disabled"
    profiles_loaded: int = 0


@dataclass
class FirewallStatus:
    tool: str           # "ufw", "firewalld", "iptables", "nftables", "none"
    active: bool
    details: str = ""


@dataclass
class SystemInfo:
    hostname: str
    kernel_version: str
    architecture: str
    cpu_model: str
    cpu_cores: int
    ram_total_mb: int
    ram_available_mb: int
    disks: list[DiskInfo] = field(default_factory=list)
    uptime_seconds: float = 0.0
    last_boot: str = ""
    distro: Optional[DistroProfile] = None
    security_tools: dict[str, bool] = field(default_factory=dict)
    mac_status: Optional[MACStatus] = None
    firewall_status: Optional[FirewallStatus] = None


def collect(distro: Optional[DistroProfile] = None) -> SystemInfo:
    """Gather all system information."""
    if distro is None:
        distro = detect_distro()

    info = SystemInfo(
        hostname=socket.gethostname(),
        kernel_version=platform.release(),
        architecture=platform.machine(),
        cpu_model=_get_cpu_model(),
        cpu_cores=os.cpu_count() or 1,
        ram_total_mb=_get_ram_total(),
        ram_available_mb=_get_ram_available(),
        distro=distro,
    )

    info.disks = _get_disk_usage()
    info.uptime_seconds = _get_uptime()
    info.last_boot = _get_last_boot()
    info.security_tools = _detect_security_tools()
    info.mac_status = _get_mac_status()
    info.firewall_status = _get_firewall_status(distro)

    return info


def _get_cpu_model() -> str:
    """Extract CPU model from /proc/cpuinfo."""
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or "Unknown"


def _get_ram_total() -> int:
    """Get total RAM in MB from /proc/meminfo."""
    return _read_meminfo("MemTotal")


def _get_ram_available() -> int:
    """Get available RAM in MB from /proc/meminfo."""
    return _read_meminfo("MemAvailable")


def _read_meminfo(key: str) -> int:
    """Read a value from /proc/meminfo and return in MB."""
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text().splitlines():
            if line.startswith(key):
                # Format: "MemTotal:       16384000 kB"
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        kb = int(parts[1])
                        return kb // 1024
                    except ValueError:
                        pass
    return 0


def _get_disk_usage() -> list[DiskInfo]:
    """Get disk usage for real filesystems."""
    disks = []
    mounts = Path("/proc/mounts")
    seen_devices = set()

    if not mounts.exists():
        return disks

    for line in mounts.read_text().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        device, mount_point = parts[0], parts[1]

        # Skip virtual filesystems
        if not device.startswith("/dev/"):
            continue
        # Skip duplicates (same device mounted multiple times)
        if device in seen_devices:
            continue
        seen_devices.add(device)

        try:
            usage = shutil.disk_usage(mount_point)
            disks.append(DiskInfo(
                mount=mount_point,
                device=device,
                total_gb=round(usage.total / (1024 ** 3), 1),
                used_gb=round(usage.used / (1024 ** 3), 1),
                free_gb=round(usage.free / (1024 ** 3), 1),
                percent_used=round(usage.used / usage.total * 100, 1) if usage.total else 0,
            ))
        except (PermissionError, OSError):
            continue

    return sorted(disks, key=lambda d: d.mount)


def _get_uptime() -> float:
    """Get system uptime in seconds from /proc/uptime."""
    uptime = Path("/proc/uptime")
    if uptime.exists():
        try:
            return float(uptime.read_text().split()[0])
        except (ValueError, IndexError):
            pass
    return 0.0


def _get_last_boot() -> str:
    """Get last boot time."""
    try:
        result = run_command(["uptime", "-s"], timeout=5)
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, Exception):
        pass
    return "Unknown"


def _detect_security_tools() -> dict[str, bool]:
    """Check which security tools are installed."""
    return {
        display_name: shutil.which(cmd) is not None
        for cmd, display_name in SECURITY_TOOLS
    }


def _get_mac_status() -> MACStatus:
    """Get Mandatory Access Control (AppArmor/SELinux) status."""
    # Check AppArmor first
    aa_enabled = Path("/sys/module/apparmor/parameters/enabled")
    if aa_enabled.exists():
        try:
            enabled = aa_enabled.read_text().strip().upper() == "Y"
            profiles = 0
            mode = "disabled"
            if enabled:
                try:
                    result = run_command(["aa-status", "--json"], timeout=10)
                    if result.returncode == 0:
                        import json
                        data = json.loads(result.stdout)
                        profiles = len(data.get("profiles", {}))
                        mode = "enforce" if profiles > 0 else "complain"
                except (FileNotFoundError, Exception):
                    mode = "enforce"
            return MACStatus(
                framework="apparmor",
                enabled=enabled,
                mode=mode,
                profiles_loaded=profiles,
            )
        except PermissionError:
            pass

    # Check SELinux
    selinux_enforce = Path("/sys/fs/selinux/enforce")
    if selinux_enforce.exists():
        try:
            enforce_val = selinux_enforce.read_text().strip()
            enforcing = enforce_val == "1"
            return MACStatus(
                framework="selinux",
                enabled=True,
                mode="enforce" if enforcing else "permissive",
            )
        except PermissionError:
            pass

    # Check via sestatus command
    if shutil.which("sestatus"):
        try:
            result = run_command(["sestatus"], timeout=5)
            if result.returncode == 0:
                enabled = "enabled" in result.stdout.lower()
                mode = "enforce" if "enforcing" in result.stdout.lower() else "permissive"
                return MACStatus(framework="selinux", enabled=enabled, mode=mode)
        except Exception:
            pass

    return MACStatus(framework="none", enabled=False, mode="disabled")


def _get_firewall_status(distro: DistroProfile) -> FirewallStatus:
    """Get firewall status."""
    # Try UFW first (Debian family)
    if shutil.which("ufw"):
        try:
            result = run_command(["ufw", "status"], timeout=10)
            if result.returncode == 0:
                active = "active" in result.stdout.lower() and "inactive" not in result.stdout.lower()
                return FirewallStatus(
                    tool="ufw",
                    active=active,
                    details=result.stdout.strip()[:200],
                )
        except Exception:
            pass

    # Try firewalld (RHEL family)
    if shutil.which("firewall-cmd"):
        try:
            result = run_command(["firewall-cmd", "--state"], timeout=10)
            active = result.returncode == 0 and "running" in result.stdout.lower()
            return FirewallStatus(
                tool="firewalld",
                active=active,
                details=result.stdout.strip(),
            )
        except Exception:
            pass

    # Try nftables
    if shutil.which("nft"):
        try:
            result = run_command(["nft", "list", "tables"], timeout=10)
            has_rules = result.returncode == 0 and result.stdout.strip()
            return FirewallStatus(
                tool="nftables",
                active=bool(has_rules),
                details=f"{len(result.stdout.splitlines())} tables loaded" if has_rules else "no tables",
            )
        except Exception:
            pass

    # Fallback to iptables
    if shutil.which("iptables"):
        try:
            result = run_command(["iptables", "-L", "-n", "--line-numbers"], timeout=10)
            if result.returncode == 0:
                lines = [l for l in result.stdout.splitlines() if l.strip() and not l.startswith("Chain") and not l.startswith("num")]
                return FirewallStatus(
                    tool="iptables",
                    active=len(lines) > 0,
                    details=f"{len(lines)} rules loaded",
                )
        except Exception:
            pass

    return FirewallStatus(tool="none", active=False, details="No firewall detected")


def format_uptime(seconds: float) -> str:
    """Format uptime seconds into human-readable string."""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)
