"""Lynis security auditing wrapper.

Wraps the lynis CLI to perform system security audits, then parses
the lynis-report.dat key-value file for structured results.
"""

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core import run_command, logger


LYNIS_REPORT_PATH = Path("/var/log/lynis-report.dat")
LYNIS_LOG_PATH = Path("/var/log/lynis.log")

# Map Lynis severity codes to LinnyTool severity
_SEVERITY_MAP = {
    "C": "Critical",
    "H": "High",
    "M": "Medium",
    "L": "Low",
    "I": "Info",
    "": "Info",
}


@dataclass
class LynisFinding:
    finding_id: str
    description: str
    details: str
    severity: str           # Critical, High, Medium, Low, Info
    finding_type: str       # "warning" or "suggestion"


@dataclass
class LynisResult:
    hardening_index: int            # 0-100
    warnings: list[LynisFinding] = field(default_factory=list)
    suggestions: list[LynisFinding] = field(default_factory=list)
    tests_performed: int = 0
    tests_skipped: int = 0
    plugins_enabled: int = 0
    lynis_version: str = ""
    report_data: dict = field(default_factory=dict)


def is_available() -> bool:
    """Check if lynis is installed."""
    return shutil.which("lynis") is not None


def scan(
    profile_path: Optional[str] = None,
    quick: bool = False,
) -> Optional[LynisResult]:
    """Run Lynis security audit.

    Args:
        profile_path: Path to custom Lynis profile (default.prf if None).
        quick: Skip interactive prompts (--quick flag).

    Returns:
        LynisResult with parsed findings, or None if scan fails.
    """
    if not is_available():
        logger.error("Lynis is not installed. Run --install-deps first.")
        return None

    cmd = ["lynis", "audit", "system", "--no-colors", "--cronjob"]
    if quick:
        cmd.append("--quick")
    if profile_path:
        cmd.extend(["--profile", profile_path])

    logger.info("Running Lynis audit...")
    result = run_command(cmd, timeout=600)

    if result.returncode not in (0, 1, 2, 4):
        # Lynis exit codes: 0=ok, 1=warning, 2=non-priv, 4=not run as root
        logger.error("Lynis failed (exit %d): %s", result.returncode, result.stderr.strip()[:300])
        return None

    # Parse report file
    if not LYNIS_REPORT_PATH.exists():
        logger.error("Lynis report not found at %s", LYNIS_REPORT_PATH)
        return None

    return _parse_report(LYNIS_REPORT_PATH)


def _parse_report(report_path: Path) -> LynisResult:
    """Parse lynis-report.dat into structured LynisResult.

    The file format is key=value with array values using [] suffix:
        hardening_index=72
        warning[]=WARN-001|Description|Details|H
        suggestion[]=SUGG-001|Description|Details|M
    """
    data: dict[str, list[str]] = {}

    try:
        content = report_path.read_text(errors="replace")
    except PermissionError:
        logger.error("Cannot read Lynis report (permission denied)")
        return LynisResult(hardening_index=0)

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()

        # Handle array keys (e.g., warning[])
        if key.endswith("[]"):
            base_key = key[:-2]
            data.setdefault(base_key, []).append(value)
        else:
            data[key] = [value]

    # Extract hardening index
    hardening_index = 0
    idx_values = data.get("hardening_index", ["0"])
    try:
        hardening_index = int(idx_values[0])
    except (ValueError, IndexError):
        pass

    # Parse warnings
    warnings = []
    for w in data.get("warning", []):
        finding = _parse_finding_line(w, "warning")
        if finding:
            warnings.append(finding)

    # Parse suggestions
    suggestions = []
    for s in data.get("suggestion", []):
        finding = _parse_finding_line(s, "suggestion")
        if finding:
            suggestions.append(finding)

    # Extract counts
    tests_performed = _get_int(data, "tests_performed")
    tests_skipped = _get_int(data, "tests_skipped")
    plugins_enabled = _get_int(data, "plugins_enabled")
    lynis_version = _get_str(data, "lynis_version")

    result = LynisResult(
        hardening_index=hardening_index,
        warnings=warnings,
        suggestions=suggestions,
        tests_performed=tests_performed,
        tests_skipped=tests_skipped,
        plugins_enabled=plugins_enabled,
        lynis_version=lynis_version,
        report_data=data,
    )

    logger.info("Lynis audit complete: hardening_index=%d, %d warnings, %d suggestions",
                hardening_index, len(warnings), len(suggestions))
    return result


def _parse_finding_line(line: str, finding_type: str) -> Optional[LynisFinding]:
    """Parse a warning or suggestion line.

    Format: ID|Description|Details|Severity
    Examples:
        AUTH-9262|Set password for single user mode|-|M
        FILE-6310|Consider restricting file permissions|/etc/crontab|H
    """
    parts = line.split("|")
    if len(parts) < 2:
        return None

    finding_id = parts[0].strip() if len(parts) > 0 else ""
    description = parts[1].strip() if len(parts) > 1 else ""
    details = parts[2].strip() if len(parts) > 2 else ""
    severity_code = parts[3].strip() if len(parts) > 3 else ""

    # Clean up details
    if details == "-" or details == "":
        details = ""

    severity = _SEVERITY_MAP.get(severity_code, "Info")

    return LynisFinding(
        finding_id=finding_id,
        description=description,
        details=details,
        severity=severity,
        finding_type=finding_type,
    )


def _get_int(data: dict, key: str) -> int:
    """Safely extract an integer value from parsed data."""
    values = data.get(key, ["0"])
    try:
        return int(values[0])
    except (ValueError, IndexError):
        return 0


def _get_str(data: dict, key: str) -> str:
    """Safely extract a string value from parsed data."""
    values = data.get(key, [""])
    return values[0] if values else ""


def get_findings_as_dicts(result: LynisResult) -> list[dict]:
    """Convert LynisResult findings to list of dicts for grading/history.

    Returns findings in the standard format used by grading.py and history.py.
    """
    findings = []

    for w in result.warnings:
        findings.append({
            "category": _map_category(w.finding_id),
            "check_name": w.finding_id,
            "severity": w.severity,
            "status": "Fail",
            "description": w.description,
            "remediation": w.details,
        })

    for s in result.suggestions:
        findings.append({
            "category": _map_category(s.finding_id),
            "check_name": s.finding_id,
            "severity": s.severity,
            "status": "Fail",
            "description": s.description,
            "remediation": s.details,
        })

    return findings


def _map_category(finding_id: str) -> str:
    """Map Lynis finding ID prefix to LinnyTool grading category."""
    prefix = finding_id.split("-")[0] if "-" in finding_id else finding_id

    category_map = {
        "AUTH": "Authentication & Users",
        "ACCT": "Authentication & Users",
        "FILE": "Filesystem & Integrity",
        "STRG": "Filesystem & Integrity",
        "PKGS": "System Updates",
        "BOOT": "System Hardening",
        "PROC": "System Hardening",
        "KRNL": "System Hardening",
        "HRDN": "System Hardening",
        "FIRE": "Network Security",
        "NETW": "Network Security",
        "SSH": "Network Security",
        "SNMP": "Network Security",
        "NAME": "Network Security",
        "MAIL": "Network Security",
        "BANN": "System Hardening",
        "SCHD": "System Hardening",
        "USB": "System Hardening",
        "LOGG": "System Hardening",
        "TIME": "System Hardening",
        "CRYP": "System Hardening",
        "CONT": "System Hardening",
        "MALW": "System Hardening",
        "TOOL": "System Hardening",
    }

    return category_map.get(prefix, "System Hardening")
