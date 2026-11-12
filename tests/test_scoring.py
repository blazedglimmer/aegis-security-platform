"""CVSS 3.1 calculator vs. known first.org reference vectors."""

import pytest

from backend.scoring import base_score, severity_for
from backend.domain import Severity


@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # unauth RCE-class
    ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),            # unauth DoS impact
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # reflected XSS canonical
    ("AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 3.7),            # low-confidentiality
    ("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),            # authed, high impact
])
def test_known_vectors(vector, expected):
    assert base_score(vector) == expected


def test_severity_bands():
    assert severity_for(0.0) is Severity.INFO
    assert severity_for(3.9) is Severity.LOW
    assert severity_for(6.1) is Severity.MEDIUM
    assert severity_for(7.5) is Severity.HIGH
    assert severity_for(9.8) is Severity.CRITICAL


def test_missing_metrics_raise():
    with pytest.raises(ValueError):
        base_score("AV:N/AC:L")
