"""
Production-style deterministic cyber risk scoring engine.

Design goals:
- Deterministic and explainable scoring
- CVSS-aware severity handling
- Asset criticality support
- Likelihood + impact calculation
- Risk bands
- Priority calculation
- Risk matrix
- Compatible with existing score() and matrix() calls

Important:
This is a risk-assessment model, not a replacement for CVSS itself.
CVSS severity and business/environmental risk are kept conceptually separate.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List


# ============================================================
# CONSTANTS
# ============================================================

SEVERITY_SCORE = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
    "info": 0,
}

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

# Asset/business criticality multiplier.
ASSET_CRITICALITY = {
    "critical": 1.00,
    "high": 0.90,
    "medium": 1.00,
    "low": 0.60,
}

# Risk bands are deliberately explicit and deterministic.
RISK_BANDS = (
    (8.0, "critical"),
    (4.5, "high"),
    (2.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
)


# ============================================================
# VALIDATION HELPERS
# ============================================================

def _normalise_severity(value: Any) -> str:
    severity = str(
        value or "info"
    ).strip().lower()

    if severity not in SEVERITY_SCORE:
        raise ValueError(
            f"Unknown severity: {value}"
        )

    return severity


def _clamp_int(
    value: Any,
    minimum: int,
    maximum: int,
    field: str
) -> int:

    try:
        value = int(value)
    except (TypeError, ValueError):
        raise ValueError(
            f"{field} must be an integer"
        )

    if not minimum <= value <= maximum:
        raise ValueError(
            f"{field} must be between "
            f"{minimum} and {maximum}"
        )

    return value


def _normalise_asset_criticality(
    value: Any
) -> str:

    criticality = str(
        value or "medium"
    ).strip().lower()

    aliases = {
        "moderate": "medium",
        "normal": "medium",
        "important": "high",
    }

    criticality = aliases.get(
        criticality,
        criticality
    )

    if criticality not in ASSET_CRITICALITY:
        criticality = "medium"

    return criticality


# ============================================================
# RISK BAND
# ============================================================

def risk_band(value: float) -> str:
    """
    Convert numerical risk into a deterministic band.
    """

    for threshold, band in RISK_BANDS:

        if value >= threshold:
            return band

    return "info"


# ============================================================
# MAIN SCORE FUNCTION
# ============================================================

def score(
    severity: str,
    likelihood: int = 3,
    impact: int | None = None,
    asset_criticality: str = "medium",
    cvss_score: float | None = None,
) -> dict:
    """
    Calculate explainable cyber risk.

    Parameters
    ----------
    severity:
        critical / high / medium / low / info

    likelihood:
        1–5

    impact:
        0–10. If omitted, severity determines the baseline.

    asset_criticality:
        critical / high / medium / low

    cvss_score:
        Optional CVSS base score. Used as contextual evidence,
        not blindly treated as business risk.
    """

    severity = _normalise_severity(
        severity
    )

    likelihood = _clamp_int(
        likelihood,
        1,
        5,
        "Likelihood"
    )

    # --------------------------------------------------------
    # Baseline impact
    # --------------------------------------------------------

    if impact is None:
        impact = SEVERITY_SCORE[
            severity
        ]
    else:
        impact = _clamp_int(
            impact,
            0,
            10,
            "Impact"
        )

    # --------------------------------------------------------
    # Asset criticality
    # --------------------------------------------------------

    criticality = _normalise_asset_criticality(
        asset_criticality
    )

    multiplier = ASSET_CRITICALITY[
        criticality
    ]

    # --------------------------------------------------------
    # Base risk
    # --------------------------------------------------------

    base_value = (
        impact *
        likelihood /
        5
    )

    adjusted_value = round(
        base_value *
        multiplier,
        1
    )

    # Keep the result inside the model's range.
    adjusted_value = max(
        0.0,
        min(10.0, adjusted_value)
    )

    band = risk_band(
        adjusted_value
    )

    # --------------------------------------------------------
    # Priority
    # --------------------------------------------------------

    if band == "critical":
        priority = 1

    elif band == "high":
        priority = 2

    elif band == "medium":
        priority = 3

    elif band == "low":
        priority = 4

    else:
        priority = 5

    # --------------------------------------------------------
    # Explainability
    # --------------------------------------------------------

    explanation = (
        f"Risk = impact ({impact}) × "
        f"likelihood ({likelihood}) / 5 × "
        f"asset criticality multiplier "
        f"({multiplier})."
    )

    result = {
        "score": adjusted_value,
        "band": band,

        "severity": severity,

        "likelihood": likelihood,

        "impact": impact,

        "asset_criticality":
            criticality,

        "criticality_multiplier":
            multiplier,

        "priority":
            priority,

        "explanation":
            explanation,
    }

    # Preserve CVSS separately.
    if cvss_score is not None:

        try:
            cvss_score = float(
                cvss_score
            )

            if 0 <= cvss_score <= 10:

                result["cvss_score"] = (
                    cvss_score
                )

        except (
            TypeError,
            ValueError
        ):
            pass

    return result


# ============================================================
# FINDING RISK BUILDER
# ============================================================

def calculate_finding_risk(
    finding: Dict[str, Any],
    asset: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Calculate risk for one finding while preserving the
    original finding data.
    """

    asset = asset or {}

    severity = _normalise_severity(
        finding.get(
            "severity",
            "info"
        )
    )

    likelihood = finding.get(
        "likelihood",
        3
    )

    impact = finding.get(
        "impact"
    )

    asset_criticality = (
        finding.get(
            "asset_criticality"
        )
        or asset.get(
            "criticality"
        )
        or asset.get(
            "asset_criticality"
        )
        or "medium"
    )

    cvss_score = finding.get(
        "cvss"
    )

    risk = score(
        severity=severity,
        likelihood=likelihood,
        impact=impact,
        asset_criticality=asset_criticality,
        cvss_score=cvss_score,
    )

    enriched = dict(
        finding
    )

    enriched["risk"] = risk

    # Convenient top-level fields for reports/UI.
    enriched["risk_score"] = (
        risk["score"]
    )

    enriched["risk_band"] = (
        risk["band"]
    )

    enriched["priority"] = (
        risk["priority"]
    )

    return enriched


# ============================================================
# RISK REGISTER
# ============================================================

def build_risk_register(
    findings: Iterable[Dict[str, Any]],
    asset: Dict[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    """
    Build a complete deterministic risk register.

    Findings are sorted by:
        1. priority
        2. risk score descending
        3. severity
    """

    asset = asset or {}

    register = []

    for finding in findings or []:

        if not isinstance(
            finding,
            dict
        ):
            continue

        register.append(
            calculate_finding_risk(
                finding,
                asset
            )
        )

    register.sort(
        key=lambda item: (
            item.get(
                "priority",
                5
            ),
            -float(
                item.get(
                    "risk_score",
                    0
                )
            ),
            -SEVERITY_ORDER.get(
                str(
                    item.get(
                        "severity",
                        "info"
                    )
                ).lower(),
                1
            ),
        )
    )

    return register


# ============================================================
# RISK MATRIX
# ============================================================

def matrix_risk_bands() -> List[List[str]]:
    """Return the baseline risk band for every likelihood/impact matrix cell.

    Impact buckets mirror matrix(): 1, 3, 5, 7, and 9. Asset criticality is
    medium (multiplier 1.0); each actual finding score still uses its asset.
    """
    impact_representatives = (1, 3, 5, 7, 9)
    return [[score("info", likelihood, impact, asset_criticality="medium")["band"]
             for impact in impact_representatives]
            for likelihood in range(1, 6)]


def matrix(
    findings: Iterable[Dict[str, Any]]
) -> List[List[int]]:
    """
    Build a 5x5 likelihood/impact matrix.

    Rows:
        likelihood 1–5

    Columns:
        impact bands 1–5

    The matrix contains finding counts.
    """

    cells = [
        [0 for _ in range(5)]
        for _ in range(5)
    ]

    for item in findings or []:

        if not isinstance(
            item,
            dict
        ):
            continue

        likelihood = max(
            1,
            min(
                5,
                int(
                    item.get(
                        "likelihood",
                        1
                    )
                )
            )
        )

        impact = max(
            0,
            min(
                10,
                int(
                    item.get(
                        "impact",
                        0
                    )
                )
            )
        )

        if impact == 0:
            impact_index = 0

        else:
            impact_index = min(
                4,
                (impact - 1) // 2
            )

        cells[
            likelihood - 1
        ][
            impact_index
        ] += 1

    return cells


# ============================================================
# SUMMARY
# ============================================================

def risk_summary(
    findings: Iterable[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Generate dashboard/report-friendly risk statistics.
    """

    findings = list(
        findings or []
    )

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    total_score = 0.0

    for finding in findings:

        band = str(
            finding.get(
                "risk_band",
                finding.get(
                    "severity",
                    "info"
                )
            )
        ).lower()

        if band in counts:
            counts[band] += 1

        try:
            total_score += float(
                finding.get(
                    "risk_score",
                    0
                )
            )

        except (
            TypeError,
            ValueError
        ):
            pass

    return {
        "total_findings":
            len(findings),

        "critical":
            counts["critical"],

        "high":
            counts["high"],

        "medium":
            counts["medium"],

        "low":
            counts["low"],

        "informational":
            counts["info"],

        "total_risk_score":
            round(
                total_score,
                1
            ),

        "risk_matrix":
            matrix(findings),
    }
