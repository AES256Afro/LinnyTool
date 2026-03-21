"""CVE vulnerability scanner.

Checks for package-level CVEs via the distro package manager, kernel CVEs
from a local database, and cross-references with NVD API 2.0 and CISA KEV.
"""

import json
import platform
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from core import run_command, logger
from core.distro_detect import DistroProfile, PkgManager


NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DATA_DIR = Path(__file__).parent.parent / "data"
LOCAL_CVE_DB = DATA_DIR / "cve_database.json"
KEV_CACHE = DATA_DIR / "cisa_kev_cache.json"
KEV_CACHE_TTL = timedelta(hours=24)


@dataclass
class CVEEntry:
    cve_id: str
    package: str
    installed_version: str
    fixed_version: str
    severity: str           # Critical, High, Medium, Low
    cvss_score: float
    description: str
    in_kev: bool = False    # In CISA Known Exploited Vulnerabilities


@dataclass
class CVEResult:
    total_packages_checked: int
    vulnerable_packages: int
    cve_list: list[CVEEntry] = field(default_factory=list)
    kernel_cves: list[CVEEntry] = field(default_factory=list)
    kev_matches: int = 0

    @property
    def total_cves(self) -> int:
        return len(self.cve_list) + len(self.kernel_cves)


def scan(profile: DistroProfile, check_kev: bool = True) -> CVEResult:
    """Run full CVE scan.

    1. Query distro package manager for security updates
    2. Check kernel CVEs from local database
    3. Cross-reference with CISA KEV feed
    """
    logger.info("Starting CVE scan...")

    # Package-level scan
    pkg_cves, total_checked = _scan_packages(profile)

    # Kernel CVE check
    kernel_version = platform.release()
    kernel_cves = _check_kernel_cves(kernel_version)

    # CISA KEV cross-reference
    kev_matches = 0
    if check_kev:
        kev_ids = _fetch_kev_catalog()
        for cve in pkg_cves + kernel_cves:
            if cve.cve_id in kev_ids:
                cve.in_kev = True
                kev_matches += 1

    result = CVEResult(
        total_packages_checked=total_checked,
        vulnerable_packages=len(set(c.package for c in pkg_cves)),
        cve_list=pkg_cves,
        kernel_cves=kernel_cves,
        kev_matches=kev_matches,
    )

    logger.info("CVE scan complete: %d package CVEs, %d kernel CVEs, %d in KEV",
                len(pkg_cves), len(kernel_cves), kev_matches)
    return result


def _scan_packages(profile: DistroProfile) -> tuple[list[CVEEntry], int]:
    """Scan for package-level CVEs using distro package manager."""
    scanners = {
        PkgManager.APT: _scan_apt,
        PkgManager.DNF: _scan_dnf,
        PkgManager.PACMAN: _scan_pacman,
        PkgManager.ZYPPER: _scan_zypper,
    }

    scanner = scanners.get(profile.pkg_manager)
    if scanner is None:
        logger.error("No CVE scanner for package manager: %s", profile.pkg_manager)
        return [], 0

    return scanner()


def _scan_apt() -> tuple[list[CVEEntry], int]:
    """Scan Debian/Ubuntu for security updates."""
    cves = []

    # Get total package count
    result = run_command(["dpkg-query", "-f", "${binary:Package}\n", "-W"], timeout=30)
    total = len(result.stdout.splitlines()) if result.returncode == 0 else 0

    # Check for security updates
    result = run_command(
        ["apt-get", "upgrade", "-s"],
        timeout=120,
    )
    if result.returncode != 0:
        return cves, total

    for line in result.stdout.splitlines():
        if "security" in line.lower() and line.startswith("Inst"):
            # Format: Inst package [current] (new_version repo) [...]
            parts = line.split()
            if len(parts) >= 4:
                package = parts[1]
                current = parts[2].strip("[]") if len(parts) > 2 else ""
                new_version = parts[3].strip("()") if len(parts) > 3 else ""

                cves.append(CVEEntry(
                    cve_id=f"UPDATE-{package}",
                    package=package,
                    installed_version=current,
                    fixed_version=new_version,
                    severity="Medium",
                    cvss_score=0.0,
                    description=f"Security update available: {package} {current} -> {new_version}",
                ))

    # Also check apt list --upgradable for more detail
    result = run_command(["apt", "list", "--upgradable"], timeout=30)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if "security" in line.lower() and "/" in line:
                parts = line.split()
                if parts:
                    pkg_name = parts[0].split("/")[0]
                    # Skip if already found
                    if not any(c.package == pkg_name for c in cves):
                        version = parts[1] if len(parts) > 1 else ""
                        cves.append(CVEEntry(
                            cve_id=f"UPDATE-{pkg_name}",
                            package=pkg_name,
                            installed_version="",
                            fixed_version=version,
                            severity="Medium",
                            cvss_score=0.0,
                            description=f"Security update available for {pkg_name}",
                        ))

    return cves, total


def _scan_dnf() -> tuple[list[CVEEntry], int]:
    """Scan RHEL/Fedora for security updates."""
    cves = []

    # Total packages
    result = run_command(["rpm", "-qa", "--queryformat", "%{NAME}\n"], timeout=30)
    total = len(result.stdout.splitlines()) if result.returncode == 0 else 0

    # Security updates
    result = run_command(["dnf", "updateinfo", "list", "security", "-q"], timeout=120)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                advisory = parts[0]
                severity = _normalize_severity(parts[1]) if len(parts) > 1 else "Medium"
                package = parts[2] if len(parts) > 2 else ""

                cves.append(CVEEntry(
                    cve_id=advisory,
                    package=package,
                    installed_version="",
                    fixed_version="",
                    severity=severity,
                    cvss_score=0.0,
                    description=f"Security advisory {advisory} for {package}",
                ))

    return cves, total


def _scan_pacman() -> tuple[list[CVEEntry], int]:
    """Scan Arch for available updates (Arch doesn't separate security updates)."""
    cves = []

    # Total packages
    result = run_command(["pacman", "-Qq"], timeout=15)
    total = len(result.stdout.splitlines()) if result.returncode == 0 else 0

    # Available updates (Arch treats all updates as potentially security-relevant)
    result = run_command(["pacman", "-Qu"], timeout=30)
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4:  # name current -> new
                pkg_name = parts[0]
                current = parts[1]
                new_version = parts[3] if len(parts) > 3 else ""
                cves.append(CVEEntry(
                    cve_id=f"UPDATE-{pkg_name}",
                    package=pkg_name,
                    installed_version=current,
                    fixed_version=new_version,
                    severity="Low",  # Can't distinguish security from feature
                    cvss_score=0.0,
                    description=f"Update available: {pkg_name} {current} -> {new_version}",
                ))

    return cves, total


def _scan_zypper() -> tuple[list[CVEEntry], int]:
    """Scan SUSE for security patches."""
    cves = []

    # Total packages
    result = run_command(["rpm", "-qa", "--queryformat", "%{NAME}\n"], timeout=30)
    total = len(result.stdout.splitlines()) if result.returncode == 0 else 0

    # Security patches
    result = run_command(
        ["zypper", "--non-interactive", "list-patches", "--category", "security"],
        timeout=120,
    )
    if result.returncode == 0:
        in_table = False
        for line in result.stdout.splitlines():
            if "---" in line:
                in_table = True
                continue
            if in_table and "|" in line:
                cols = [c.strip() for c in line.split("|")]
                if len(cols) >= 5:
                    cves.append(CVEEntry(
                        cve_id=cols[1] if len(cols) > 1 else "",
                        package=cols[0],
                        installed_version="",
                        fixed_version=cols[2] if len(cols) > 2 else "",
                        severity=_normalize_severity(cols[3] if len(cols) > 3 else ""),
                        cvss_score=0.0,
                        description=f"Security patch: {cols[0]}",
                    ))

    return cves, total


def _check_kernel_cves(kernel_version: str) -> list[CVEEntry]:
    """Check local CVE database for known kernel vulnerabilities."""
    db = _load_local_db()
    kernel_cves = db.get("kernel", [])
    matches = []

    for entry in kernel_cves:
        affected_versions = entry.get("affected_versions", [])
        # Simple version prefix matching
        for av in affected_versions:
            if kernel_version.startswith(av) or av == "*":
                fixed = entry.get("fixed_version", "")
                if fixed and _version_gte(kernel_version, fixed):
                    continue  # Already patched
                matches.append(CVEEntry(
                    cve_id=entry.get("cve_id", ""),
                    package="linux-kernel",
                    installed_version=kernel_version,
                    fixed_version=fixed,
                    severity=_normalize_severity(entry.get("severity", "High")),
                    cvss_score=entry.get("cvss_score", 0.0),
                    description=entry.get("description", ""),
                ))
                break

    return matches


def _fetch_kev_catalog() -> set[str]:
    """Fetch CISA KEV catalog, using cache if fresh."""
    # Check cache
    if KEV_CACHE.exists():
        try:
            cache_data = json.loads(KEV_CACHE.read_text())
            cached_time = datetime.fromisoformat(cache_data.get("fetched_at", ""))
            if datetime.now() - cached_time < KEV_CACHE_TTL:
                return set(cache_data.get("cve_ids", []))
        except (json.JSONDecodeError, ValueError):
            pass

    # Fetch fresh
    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={"User-Agent": "LinnyTool/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            cve_ids = [v["cveID"] for v in data.get("vulnerabilities", [])]

            # Cache result
            KEV_CACHE.parent.mkdir(parents=True, exist_ok=True)
            KEV_CACHE.write_text(json.dumps({
                "fetched_at": datetime.now().isoformat(),
                "cve_ids": cve_ids,
            }))

            return set(cve_ids)
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to fetch CISA KEV catalog: %s", e)
        return set()


def _load_local_db() -> dict:
    """Load the local CVE database."""
    if not LOCAL_CVE_DB.exists():
        return {}
    try:
        return json.loads(LOCAL_CVE_DB.read_text())
    except (json.JSONDecodeError, PermissionError):
        return {}


def _normalize_severity(severity: str) -> str:
    """Normalize severity string to Critical/High/Medium/Low."""
    s = severity.strip().lower()
    mapping = {
        "critical": "Critical",
        "important": "High",
        "high": "High",
        "moderate": "Medium",
        "medium": "Medium",
        "low": "Low",
        "negligible": "Low",
    }
    return mapping.get(s, "Medium")


def _version_gte(current: str, target: str) -> bool:
    """Simple version comparison: is current >= target?"""
    try:
        cur_parts = [int(x) for x in current.split(".")[:3]]
        tgt_parts = [int(x) for x in target.split(".")[:3]]
        return cur_parts >= tgt_parts
    except ValueError:
        return False


def get_findings_as_dicts(result: CVEResult) -> list[dict]:
    """Convert CVEResult to standard findings dict format."""
    findings = []
    for cve in result.cve_list + result.kernel_cves:
        desc = cve.description
        if cve.in_kev:
            desc += " [CISA KEV - Known Exploited]"
        findings.append({
            "category": "CVE Exposure",
            "check_name": cve.cve_id,
            "severity": cve.severity,
            "status": "Fail",
            "description": desc,
            "remediation": f"Update {cve.package} to {cve.fixed_version}" if cve.fixed_version else "Apply available security updates",
        })
    return findings
