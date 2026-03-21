"""OpenSCAP compliance scanner wrapper.

Wraps the oscap CLI to evaluate system security against CIS, DISA-STIG,
and other SCAP profiles. Parses XCCDF results XML for structured output.
"""

import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core import run_command, logger
from core.distro_detect import DistroProfile

SCAP_CONTENT_DIR = Path("/usr/share/xml/scap/ssg/content")

# Namespace for XCCDF 1.2
XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"

# Profile selection preference order
PROFILE_PREFERENCE = [
    "cis_level1_server",
    "cis_level2_server",
    "cis",
    "standard",
    "stig",
    "cis_level1_workstation",
    "cis_level2_workstation",
    "pci-dss",
]


@dataclass
class RuleResult:
    rule_id: str
    title: str
    result: str         # "pass", "fail", "error", "notapplicable", "notchecked"
    severity: str       # "high", "medium", "low", "unknown"
    description: str = ""


@dataclass
class ScapResult:
    profile_id: str
    profile_title: str
    total_rules: int
    passed: int
    failed: int
    error: int
    not_applicable: int
    not_checked: int
    score: float                        # 0-100
    rule_results: list[RuleResult] = field(default_factory=list)
    html_report_path: Optional[str] = None
    raw_xml_path: Optional[str] = None


def is_available() -> bool:
    """Check if oscap is installed."""
    return shutil.which("oscap") is not None


def scan(
    profile: DistroProfile,
    scap_profile: Optional[str] = None,
    report_dir: Optional[Path] = None,
) -> Optional[ScapResult]:
    """Run OpenSCAP evaluation against the system.

    Args:
        profile: Detected distro profile.
        scap_profile: Specific XCCDF profile ID to use (auto-selected if None).
        report_dir: Directory for HTML report and results XML.

    Returns:
        ScapResult with findings, or None if scan cannot be run.
    """
    if not is_available():
        logger.error("oscap is not installed. Run --install-deps first.")
        return None

    content_file = profile.scap_content_file
    if not content_file:
        content_file = _find_content_file(profile)
    if not content_file or not Path(content_file).exists():
        logger.error("No SCAP content available for %s", profile.display_name)
        return None

    # Select profile
    if scap_profile is None:
        scap_profile = _auto_select_profile(content_file)
    if scap_profile is None:
        logger.error("No suitable SCAP profile found in %s", content_file)
        return None

    # Ensure profile has xccdf_org.ssgproject.content_profile_ prefix
    if not scap_profile.startswith("xccdf_"):
        scap_profile = f"xccdf_org.ssgproject.content_profile_{scap_profile}"

    # Set up output paths
    if report_dir is None:
        report_dir = Path.home() / "LinnyTool_Reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    results_xml = report_dir / "oscap_results.xml"
    report_html = report_dir / "oscap_report.html"

    # Build command
    cmd = [
        "oscap", "xccdf", "eval",
        "--profile", scap_profile,
        "--results", str(results_xml),
        "--report", str(report_html),
        content_file,
    ]

    logger.info("Running OpenSCAP scan with profile: %s", scap_profile)
    logger.info("Content file: %s", content_file)

    result = run_command(cmd, timeout=600)

    # oscap returns: 0 = all pass, 1 = error, 2 = some checks failed (normal)
    if result.returncode == 1:
        logger.error("OpenSCAP error: %s", result.stderr.strip()[:500])
        return None

    if not results_xml.exists():
        logger.error("Results XML not generated")
        return None

    # Parse results
    scap_result = _parse_results_xml(results_xml)
    if scap_result:
        scap_result.html_report_path = str(report_html) if report_html.exists() else None
        scap_result.raw_xml_path = str(results_xml)
        logger.info("OpenSCAP scan complete: %d/%d passed (%.1f%%)",
                     scap_result.passed, scap_result.total_rules, scap_result.score)

    return scap_result


def list_profiles(profile: DistroProfile) -> list[dict]:
    """List available SCAP profiles for the detected distro.

    Returns:
        List of dicts with 'id' and 'title'.
    """
    content_file = profile.scap_content_file
    if not content_file:
        content_file = _find_content_file(profile)
    if not content_file:
        return []

    if not is_available():
        return []

    result = run_command(
        ["oscap", "info", "--profiles", content_file],
        timeout=30,
    )

    profiles = []
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            line = line.strip()
            if ":" in line:
                profile_id, _, title = line.partition(":")
                profiles.append({
                    "id": profile_id.strip(),
                    "title": title.strip(),
                })

    return profiles


def _find_content_file(profile: DistroProfile) -> Optional[str]:
    """Find the best SCAP content file for this distro."""
    if not SCAP_CONTENT_DIR.exists():
        return None

    # Try distro-specific content
    version_norm = profile.version.replace(".", "")
    candidates = [
        f"ssg-{profile.id}{version_norm}-ds.xml",
        f"ssg-{profile.id}-ds.xml",
    ]

    for candidate in candidates:
        path = SCAP_CONTENT_DIR / candidate
        if path.exists():
            return str(path)

    # Broader search
    for ds_file in sorted(SCAP_CONTENT_DIR.glob("ssg-*-ds.xml")):
        name = ds_file.stem.replace("ssg-", "").replace("-ds", "")
        if profile.id in name:
            return str(ds_file)

    return None


def _auto_select_profile(content_file: str) -> Optional[str]:
    """Select the best profile from available ones."""
    profiles = []

    if is_available():
        result = run_command(
            ["oscap", "info", "--profiles", content_file],
            timeout=30,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if ":" in line:
                    profile_id = line.split(":")[0].strip()
                    profiles.append(profile_id)

    if not profiles:
        return None

    # Try each preferred profile
    for pref in PROFILE_PREFERENCE:
        for available in profiles:
            # Match by suffix (the profile ID may have a long prefix)
            if available.endswith(pref) or pref in available:
                return available

    # Fall back to first available
    return profiles[0] if profiles else None


def _parse_results_xml(xml_path: Path) -> Optional[ScapResult]:
    """Parse XCCDF results XML into ScapResult."""
    try:
        tree = ET.parse(str(xml_path))
        root = tree.getroot()
    except ET.ParseError as e:
        logger.error("Failed to parse XCCDF results: %s", e)
        return None

    # Find the TestResult element
    test_result = root.find(f".//{{{XCCDF_NS}}}TestResult")
    if test_result is None:
        # Try without namespace (some versions)
        test_result = root.find(".//TestResult")
    if test_result is None:
        logger.error("No TestResult element in results XML")
        return None

    # Get profile info
    profile_elem = test_result.find(f"{{{XCCDF_NS}}}profile") or test_result.find("profile")
    profile_id = ""
    if profile_elem is not None:
        profile_id = profile_elem.get("idref", "")

    # Get score
    score = 0.0
    score_elem = test_result.find(f"{{{XCCDF_NS}}}score") or test_result.find("score")
    if score_elem is not None and score_elem.text:
        try:
            score = float(score_elem.text)
        except ValueError:
            pass

    # Parse rule results
    rule_results = []
    counts = {"pass": 0, "fail": 0, "error": 0, "notapplicable": 0, "notchecked": 0}

    for rr in test_result.findall(f"{{{XCCDF_NS}}}rule-result"):
        if rr is None:
            continue

        rule_id = rr.get("idref", "")
        severity = rr.get("severity", "unknown")

        result_elem = rr.find(f"{{{XCCDF_NS}}}result") or rr.find("result")
        result_text = result_elem.text.strip().lower() if result_elem is not None and result_elem.text else "notchecked"

        # Normalize result
        if result_text in counts:
            counts[result_text] += 1
        elif result_text == "informational" or result_text == "fixed":
            counts["pass"] += 1
            result_text = "pass"
        else:
            counts["notchecked"] += 1

        rule_results.append(RuleResult(
            rule_id=rule_id,
            title=_get_rule_title(root, rule_id),
            result=result_text,
            severity=severity,
        ))

    # Also try without namespace
    if not rule_results:
        for rr in test_result.findall("rule-result"):
            rule_id = rr.get("idref", "")
            severity = rr.get("severity", "unknown")
            result_elem = rr.find("result")
            result_text = result_elem.text.strip().lower() if result_elem is not None and result_elem.text else "notchecked"
            if result_text in counts:
                counts[result_text] += 1
            rule_results.append(RuleResult(
                rule_id=rule_id, title="", result=result_text, severity=severity,
            ))

    total = sum(counts.values())

    return ScapResult(
        profile_id=profile_id,
        profile_title=_get_profile_title(root, profile_id),
        total_rules=total,
        passed=counts["pass"],
        failed=counts["fail"],
        error=counts["error"],
        not_applicable=counts["notapplicable"],
        not_checked=counts["notchecked"],
        score=score,
        rule_results=rule_results,
    )


def _get_rule_title(root: ET.Element, rule_id: str) -> str:
    """Look up a rule's title from the Benchmark section."""
    for rule in root.iter(f"{{{XCCDF_NS}}}Rule"):
        if rule.get("id") == rule_id:
            title = rule.find(f"{{{XCCDF_NS}}}title")
            if title is not None and title.text:
                return title.text.strip()
    return ""


def _get_profile_title(root: ET.Element, profile_id: str) -> str:
    """Look up a profile's title."""
    for prof in root.iter(f"{{{XCCDF_NS}}}Profile"):
        if prof.get("id") == profile_id:
            title = prof.find(f"{{{XCCDF_NS}}}title")
            if title is not None and title.text:
                return title.text.strip()
    return profile_id
