"""Security grading system — A+ through F.

Mirrors WinnyTool's weighted scoring across 7 categories with
severity-based deductions. Each category starts at 100 and deductions
are applied per failed finding.
"""

from dataclasses import dataclass, field

from core import logger


# Grade scale (same as WinnyTool)
GRADE_SCALE = [
    ("A+", 97, 100),
    ("A",  93, 96),
    ("A-", 90, 92),
    ("B+", 87, 89),
    ("B",  83, 86),
    ("B-", 80, 82),
    ("C+", 77, 79),
    ("C",  73, 76),
    ("C-", 70, 72),
    ("D+", 67, 69),
    ("D",  63, 66),
    ("D-", 60, 62),
    ("F",   0, 59),
]

# Category weights (must sum to 1.0)
CATEGORIES = {
    "System Updates":           0.20,
    "CVE Exposure":             0.20,
    "System Hardening":         0.20,
    "Network Security":         0.15,
    "Access Control":           0.10,
    "Authentication & Users":   0.10,
    "Filesystem & Integrity":   0.05,
}

# Points deducted per failing check based on severity
SEVERITY_DEDUCTIONS = {
    "Critical": 20,
    "High":     15,
    "Medium":   10,
    "Low":       5,
    "Info":      0,
}


@dataclass
class Deduction:
    check_name: str
    severity: str
    points: int


@dataclass
class CategoryScore:
    name: str
    weight: float
    base_score: float = 100.0
    deductions: list[Deduction] = field(default_factory=list)
    findings_pass: int = 0
    findings_fail: int = 0

    @property
    def total_deductions(self) -> float:
        return sum(d.points for d in self.deductions)

    @property
    def final_score(self) -> float:
        return max(0.0, min(100.0, self.base_score - self.total_deductions))

    @property
    def weighted_score(self) -> float:
        return self.final_score * self.weight


@dataclass
class GradeResult:
    overall_score: float
    overall_grade: str
    categories: list[CategoryScore] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(c.findings_pass + c.findings_fail for c in self.categories)

    @property
    def total_pass(self) -> int:
        return sum(c.findings_pass for c in self.categories)

    @property
    def total_fail(self) -> int:
        return sum(c.findings_fail for c in self.categories)

    @property
    def critical_count(self) -> int:
        return self._count_severity("Critical")

    @property
    def high_count(self) -> int:
        return self._count_severity("High")

    @property
    def medium_count(self) -> int:
        return self._count_severity("Medium")

    @property
    def low_count(self) -> int:
        return self._count_severity("Low")

    def _count_severity(self, severity: str) -> int:
        return sum(
            1 for c in self.categories
            for d in c.deductions if d.severity == severity
        )


def calculate_grade(findings: list[dict]) -> GradeResult:
    """Calculate overall security grade from scan findings.

    Args:
        findings: List of dicts with keys:
            - category: str (must match a key in CATEGORIES)
            - check_name: str
            - severity: str (Critical, High, Medium, Low, Info)
            - status: str (Pass, Fail, Error, Skip)
            - description: str (optional)

    Returns:
        GradeResult with overall score, grade, and per-category breakdown.
    """
    # Initialize category scores
    cat_scores: dict[str, CategoryScore] = {}
    for name, weight in CATEGORIES.items():
        cat_scores[name] = CategoryScore(name=name, weight=weight)

    # Process findings
    for finding in findings:
        category = finding.get("category", "System Hardening")
        status = finding.get("status", "Fail")
        severity = finding.get("severity", "Medium")
        check_name = finding.get("check_name", "")

        # Map unknown categories to System Hardening
        if category not in cat_scores:
            category = "System Hardening"

        cat = cat_scores[category]

        if status == "Pass":
            cat.findings_pass += 1
        elif status in ("Fail", "Error"):
            cat.findings_fail += 1
            deduction = SEVERITY_DEDUCTIONS.get(severity, 5)
            cat.deductions.append(Deduction(
                check_name=check_name,
                severity=severity,
                points=deduction,
            ))

    # Calculate weighted average
    categories = list(cat_scores.values())

    # Only weight categories that have findings
    active_cats = [c for c in categories if c.findings_pass + c.findings_fail > 0]
    if active_cats:
        # Re-normalize weights for active categories
        total_weight = sum(c.weight for c in active_cats)
        if total_weight > 0:
            overall = sum(c.final_score * (c.weight / total_weight) for c in active_cats)
        else:
            overall = 100.0
    else:
        overall = 100.0

    overall = round(max(0.0, min(100.0, overall)), 1)
    grade = score_to_grade(overall)

    result = GradeResult(
        overall_score=overall,
        overall_grade=grade,
        categories=categories,
    )

    logger.info("Grade calculated: %s (%.1f) — %d pass, %d fail",
                grade, overall, result.total_pass, result.total_fail)
    return result


def score_to_grade(score: float) -> str:
    """Map numeric score (0-100) to letter grade."""
    score = round(score)
    for grade, low, high in GRADE_SCALE:
        if low <= score <= high:
            return grade
    return "F"


def grade_color(grade: str) -> str:
    """Return ANSI color code for a grade."""
    if grade.startswith("A"):
        return "\033[92m"   # bright green
    elif grade.startswith("B"):
        return "\033[94m"   # bright blue
    elif grade.startswith("C"):
        return "\033[93m"   # bright yellow
    elif grade.startswith("D"):
        return "\033[91m"   # bright red
    else:
        return "\033[31m"   # red


def grade_color_hex(grade: str) -> str:
    """Return hex color for a grade (for HTML reports)."""
    if grade.startswith("A"):
        return "#28a745"
    elif grade.startswith("B"):
        return "#17a2b8"
    elif grade.startswith("C"):
        return "#ffc107"
    elif grade.startswith("D"):
        return "#fd7e14"
    else:
        return "#dc3545"
