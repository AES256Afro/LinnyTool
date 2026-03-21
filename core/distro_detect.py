"""Distro detection and environment profiling.

Single source of truth for OS identity, package manager, container type,
SCAP content availability, and init system. Every other module imports from here.
"""

import os
import platform
import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from core import run_command, logger


class DistroFamily(Enum):
    DEBIAN = "debian"
    RHEL = "rhel"
    ARCH = "arch"
    SUSE = "suse"
    UNKNOWN = "unknown"


class PkgManager(Enum):
    APT = "apt"
    DNF = "dnf"
    PACMAN = "pacman"
    ZYPPER = "zypper"
    UNKNOWN = "unknown"


class ContainerType(Enum):
    NONE = "none"
    DOCKER = "docker"
    LXC = "lxc"
    WSL = "wsl"
    PODMAN = "podman"


# Map distro IDs to families
_FAMILY_MAP: dict[str, DistroFamily] = {
    "ubuntu": DistroFamily.DEBIAN,
    "debian": DistroFamily.DEBIAN,
    "linuxmint": DistroFamily.DEBIAN,
    "pop": DistroFamily.DEBIAN,
    "elementary": DistroFamily.DEBIAN,
    "kali": DistroFamily.DEBIAN,
    "raspbian": DistroFamily.DEBIAN,
    "zorin": DistroFamily.DEBIAN,
    "rhel": DistroFamily.RHEL,
    "centos": DistroFamily.RHEL,
    "fedora": DistroFamily.RHEL,
    "rocky": DistroFamily.RHEL,
    "almalinux": DistroFamily.RHEL,
    "ol": DistroFamily.RHEL,
    "oracle": DistroFamily.RHEL,
    "amzn": DistroFamily.RHEL,
    "arch": DistroFamily.ARCH,
    "manjaro": DistroFamily.ARCH,
    "endeavouros": DistroFamily.ARCH,
    "garuda": DistroFamily.ARCH,
    "opensuse-leap": DistroFamily.SUSE,
    "opensuse-tumbleweed": DistroFamily.SUSE,
    "sles": DistroFamily.SUSE,
    "sled": DistroFamily.SUSE,
}

# Map families to package managers
_PKG_MAP: dict[DistroFamily, PkgManager] = {
    DistroFamily.DEBIAN: PkgManager.APT,
    DistroFamily.RHEL: PkgManager.DNF,
    DistroFamily.ARCH: PkgManager.PACMAN,
    DistroFamily.SUSE: PkgManager.ZYPPER,
}

# SCAP content ID mappings (distro_id -> list of content prefixes to try)
_SCAP_MAP: dict[str, list[str]] = {
    "ubuntu": ["ubuntu2404", "ubuntu2204", "ubuntu2004", "ubuntu1804"],
    "debian": ["debian12", "debian11"],
    "rhel": ["rhel10", "rhel9", "rhel8"],
    "centos": ["centos8"],
    "fedora": ["fedora"],
    "rocky": ["rhel9", "rhel8"],
    "almalinux": ["almalinux9", "rhel9"],
    "ol": ["ol10", "ol9", "ol8", "ol7"],
    "oracle": ["ol10", "ol9", "ol8", "ol7"],
    "opensuse-leap": ["opensuse"],
    "opensuse-tumbleweed": ["opensuse"],
    "sles": ["sle15", "sle12"],
    "sled": ["sle15", "sle12"],
}

SCAP_CONTENT_DIR = Path("/usr/share/xml/scap/ssg/content")


@dataclass
class DistroProfile:
    """Complete environment profile for the detected system."""

    name: str
    version: str
    version_codename: str
    family: DistroFamily
    pkg_manager: PkgManager
    id: str
    id_like: list[str] = field(default_factory=list)
    container: ContainerType = ContainerType.NONE
    is_server: bool = True
    scap_content_file: Optional[str] = None
    init_system: str = "systemd"

    @property
    def display_name(self) -> str:
        return f"{self.name} {self.version}"


def detect() -> DistroProfile:
    """Detect the current system's distro, environment, and capabilities."""
    os_info = _parse_os_release()

    os_id = os_info.get("ID", "unknown").lower().strip('"')
    id_like = os_info.get("ID_LIKE", "").strip('"').split()
    name = os_info.get("NAME", os_info.get("PRETTY_NAME", "Unknown")).strip('"')
    version = os_info.get("VERSION_ID", "0").strip('"')
    codename = os_info.get("VERSION_CODENAME", "").strip('"')

    family = _detect_family(os_id, id_like)
    pkg_manager = _PKG_MAP.get(family, PkgManager.UNKNOWN)
    container = _detect_container()
    is_server = not _detect_desktop()
    scap_file = _find_scap_content(os_id, version)
    init_system = _detect_init_system()

    profile = DistroProfile(
        name=name,
        version=version,
        version_codename=codename,
        family=family,
        pkg_manager=pkg_manager,
        id=os_id,
        id_like=id_like,
        container=container,
        is_server=is_server,
        scap_content_file=scap_file,
        init_system=init_system,
    )

    logger.info("Detected: %s (family=%s, pkg=%s, container=%s)",
                profile.display_name, family.value, pkg_manager.value, container.value)
    return profile


def _parse_os_release() -> dict[str, str]:
    """Parse /etc/os-release into key-value dict."""
    result = {}
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        # Fallback
        os_release = Path("/usr/lib/os-release")
    if os_release.exists():
        for line in os_release.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                result[key] = value.strip('"')
    return result


def _detect_family(os_id: str, id_like: list[str]) -> DistroFamily:
    """Map OS ID to family, using ID_LIKE as fallback."""
    if os_id in _FAMILY_MAP:
        return _FAMILY_MAP[os_id]
    for like_id in id_like:
        like_id = like_id.lower()
        if like_id in _FAMILY_MAP:
            return _FAMILY_MAP[like_id]
    return DistroFamily.UNKNOWN


def _detect_container() -> ContainerType:
    """Detect if running inside a container or WSL."""
    # Docker
    if Path("/.dockerenv").exists():
        return ContainerType.DOCKER

    # Podman
    if Path("/run/.containerenv").exists():
        return ContainerType.PODMAN

    # Check cgroup for container indicators
    cgroup = Path("/proc/1/cgroup")
    if cgroup.exists():
        try:
            content = cgroup.read_text()
            if "docker" in content:
                return ContainerType.DOCKER
            if "lxc" in content:
                return ContainerType.LXC
            if "kubepods" in content:
                return ContainerType.DOCKER
        except PermissionError:
            pass

    # WSL
    proc_version = Path("/proc/version")
    if proc_version.exists():
        try:
            content = proc_version.read_text().lower()
            if "microsoft" in content or "wsl" in content:
                return ContainerType.WSL
        except PermissionError:
            pass

    return ContainerType.NONE


def _detect_desktop() -> bool:
    """Check if a desktop environment is running."""
    # Check environment variables
    if any(os.environ.get(var) for var in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_CURRENT_DESKTOP")):
        # Verify a desktop session is actually active
        session = os.environ.get("XDG_SESSION_TYPE", "")
        if session in ("x11", "wayland"):
            return True
        desktop = os.environ.get("XDG_CURRENT_DESKTOP", "")
        if desktop:
            return True

    # Check for display managers
    for dm in ("gdm", "lightdm", "sddm", "lxdm"):
        if shutil.which(dm):
            return True

    return False


def _find_scap_content(os_id: str, version: str) -> Optional[str]:
    """Find the best matching SCAP content file for this distro."""
    if not SCAP_CONTENT_DIR.exists():
        logger.debug("SCAP content directory not found: %s", SCAP_CONTENT_DIR)
        return None

    # Try exact version match first (e.g., ubuntu2404 for Ubuntu 24.04)
    version_normalized = version.replace(".", "")
    exact_name = f"ssg-{os_id}{version_normalized}-ds.xml"
    exact_path = SCAP_CONTENT_DIR / exact_name
    if exact_path.exists():
        return str(exact_path)

    # Try mapped content IDs
    content_ids = _SCAP_MAP.get(os_id, [])
    for content_id in content_ids:
        candidate = SCAP_CONTENT_DIR / f"ssg-{content_id}-ds.xml"
        if candidate.exists():
            logger.info("Using SCAP content %s (no exact match for %s %s)",
                        candidate.name, os_id, version)
            return str(candidate)

    # Try family-level fallbacks via ID_LIKE
    os_info = _parse_os_release()
    for like_id in os_info.get("ID_LIKE", "").strip('"').split():
        content_ids = _SCAP_MAP.get(like_id, [])
        for content_id in content_ids:
            candidate = SCAP_CONTENT_DIR / f"ssg-{content_id}-ds.xml"
            if candidate.exists():
                logger.info("Using SCAP content %s via ID_LIKE fallback", candidate.name)
                return str(candidate)

    # List all available and pick first
    available = sorted(SCAP_CONTENT_DIR.glob("ssg-*-ds.xml"))
    if available:
        logger.warning("No SCAP content match for %s %s, available: %s",
                        os_id, version, [f.name for f in available[:5]])
    return None


def _detect_init_system() -> str:
    """Detect the init system in use."""
    if Path("/run/systemd/system").exists():
        return "systemd"
    try:
        result = run_command(["/sbin/init", "--version"], timeout=5)
        if "upstart" in result.stdout.lower():
            return "upstart"
        if "sysv" in result.stdout.lower():
            return "sysvinit"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    if Path("/etc/init.d").exists() and not Path("/run/systemd/system").exists():
        return "sysvinit"
    if shutil.which("openrc"):
        return "openrc"
    return "unknown"
