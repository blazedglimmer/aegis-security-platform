"""CVSS 3.1 base-score calculator.

The Analysis agent assigns a CVSS *vector* (a defensible, auditable statement of
the metrics); the numeric score is computed here by the official formula, not
estimated by the model. This keeps severity reproducible and comparable.
"""

from __future__ import annotations

import math

from .domain import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(x: float) -> float:
    # CVSS 3.1 Appendix A roundup: ceil to one decimal with float-safety.
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in vector.strip().split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.upper()] = v.upper()
    return out


def base_score(vector: str) -> float:
    """Compute the CVSS 3.1 base score from a vector string.

    Accepts an optional ``CVSS:3.1/`` prefix. Raises ``ValueError`` if required
    metrics are missing.
    """
    m = parse_vector(vector)
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [r for r in required if r not in m]
    if missing:
        raise ValueError(f"CVSS vector missing metrics: {missing}")

    scope_changed = m["S"] == "C"
    pr_table = _PR_C if scope_changed else _PR_U

    iss = 1 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]

    if impact <= 0:
        return 0.0
    raw = (impact + exploitability) * (1.08 if scope_changed else 1.0)
    return _roundup(min(raw, 10.0))


def severity_for(score: float) -> Severity:
    if score == 0:
        return Severity.INFO
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL
