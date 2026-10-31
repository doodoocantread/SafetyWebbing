"""Unit tests for the benchmark core (matcher + scoring + spec).

All pure: no server, no Docker. Reports are hand-built `Report.model_dump()`-shaped
dicts so the detection logic can be checked exactly.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from safetywebbing.benchmark.cli import score_records
from safetywebbing.benchmark.matcher import match_report, normalize_cwe
from safetywebbing.benchmark.runner import RunRecord
from safetywebbing.benchmark.scoring import score_case
from safetywebbing.benchmark.spec import (
    ExpectedFinding,
    GroundTruth,
    load_ground_truth,
    load_ground_truth_dir,
    load_suite,
)

_GT_DIR = Path(__file__).resolve().parents[1] / "benchmark" / "ground_truth"


def _finding(cwe=None, owasp=None, severity=None, vuln_class="SQL Injection",
             request="curl http://localhost:3000/rest/user/login", target="http://localhost:3000"):
    return {
        "id": "f1", "request": request, "target": target, "response": "",
        "label": {"vuln_class": vuln_class, "severity": severity, "cwe": cwe, "owasp": owasp},
    }


def _report(findings, status="completed"):
    return {"run_id": "r", "goal": "g", "targets": ["http://localhost:3000"],
            "status": status, "engine": "replay", "findings": findings}


# --- normalize_cwe ---------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [
    ("CWE-89", "89"), ("cwe89", "89"), (" 89 ", "89"), ("89", "89"), (None, ""), ("", ""),
])
def test_normalize_cwe(raw, expected):
    assert normalize_cwe(raw) == expected


# --- spec ------------------------------------------------------------------------


def test_ground_truth_files_parse():
    gts = load_ground_truth_dir(_GT_DIR)
    assert {"juice-shop", "dvwa", "bwapp"} <= set(gts)
    for gt in gts.values():
        assert gt.origin.startswith("http://localhost")
        assert gt.expected


def test_for_scan_type_general_is_everything():
    gt = load_ground_truth(_GT_DIR / "dvwa.json")
    assert len(gt.for_scan_type("general")) == len(gt.expected)
    assert all(e.scan_type == "sqli" for e in gt.for_scan_type("sqli"))


def test_suite_parses():
    suite = load_suite(Path(__file__).resolve().parents[1] / "benchmark" / "suites" / "default.json")
    assert suite.repeat >= 1
    assert any(c.target == "juice-shop" for c in suite.cases)


def test_bad_scan_type_rejected():
    with pytest.raises(ValueError):
        ExpectedFinding(id="x", scan_type="nope", vuln_class="SQLi")


# --- matcher ---------------------------------------------------------------------


_SQLI = ExpectedFinding(id="e1", scan_type="sqli", vuln_class="SQL Injection",
                        cwe="CWE-89", owasp="A03:2021 - Injection",
                        endpoint="/rest/user/login", severity="critical")


def test_match_by_cwe_and_endpoint():
    rep = _report([_finding(cwe="CWE-89", owasp="A03:2021 - Injection", severity="critical")])
    res = match_report(rep, "http://localhost:3000", [_SQLI], "sqli")
    o = res.outcomes[0]
    assert o.found and o.cwe_correct and o.owasp_correct
    assert o.severity_delta == 0
    assert res.unmatched_finding_count == 0


def test_endpoint_id_collapse_matches():
    exp = ExpectedFinding(id="e", scan_type="auth", vuln_class="Broken Access Control",
                          cwe="CWE-639", endpoint="/rest/basket/:id")
    rep = _report([_finding(cwe="CWE-639", vuln_class="Broken Access Control",
                            request="curl http://localhost:3000/rest/basket/42",
                            target="http://localhost:3000")])
    res = match_report(rep, "http://localhost:3000", [exp], "auth")
    assert res.outcomes[0].found


def test_wrong_endpoint_does_not_match():
    rep = _report([_finding(cwe="CWE-89", request="curl http://localhost:3000/rest/products/search")])
    res = match_report(rep, "http://localhost:3000", [_SQLI], "sqli")
    assert not res.outcomes[0].found
    assert res.unmatched_finding_count == 1  # finding present but matched nothing


def test_class_fallback_when_cwe_missing():
    exp = ExpectedFinding(id="e", scan_type="xss", vuln_class="Cross-Site Scripting",
                          endpoint="*")
    rep = _report([_finding(cwe=None, vuln_class="Cross-Site Scripting (reflected)",
                            request="curl http://localhost:3000/x")])
    res = match_report(rep, "http://localhost:3000", [exp], "xss")
    assert res.outcomes[0].found
    assert not res.outcomes[0].cwe_correct  # found, but no CWE to credit


def test_other_origin_ignored():
    rep = _report([_finding(cwe="CWE-89", target="http://localhost:9999",
                            request="curl http://localhost:9999/rest/user/login")])
    res = match_report(rep, "http://localhost:3000", [_SQLI], "sqli")
    assert not res.outcomes[0].found
    assert res.total_findings == 0  # off-origin finding excluded entirely


def test_one_finding_matches_one_expected():
    exp2 = ExpectedFinding(id="e2", scan_type="sqli", vuln_class="SQL Injection",
                           cwe="CWE-89", endpoint="/rest/user/login")
    rep = _report([_finding(cwe="CWE-89")])  # single finding
    res = match_report(rep, "http://localhost:3000", [_SQLI, exp2], "sqli")
    assert sum(o.found for o in res.outcomes) == 1  # greedy one-to-one


# --- scoring ---------------------------------------------------------------------


def test_score_case_recall_precision():
    exp = [_SQLI,
           ExpectedFinding(id="e2", scan_type="sqli", vuln_class="SQL Injection",
                           cwe="CWE-89", endpoint="/rest/products/search")]
    rep = _report([
        _finding(cwe="CWE-89", severity="critical"),  # matches e1
        _finding(cwe="CWE-79", vuln_class="XSS",
                 request="curl http://localhost:3000/unknown"),  # unmatched
    ])
    m = match_report(rep, "http://localhost:3000", exp, "sqli")
    score = score_case("juice-shop", "sqli", [m])
    assert score.recall_mean == 0.5  # 1 of 2 expected
    assert score.precision_mean == 0.5  # 1 of 2 findings matched
    assert 0 < score.f1_mean < 1


def test_reproducibility_flaky():
    exp = [_SQLI]
    found = match_report(_report([_finding(cwe="CWE-89")]), "http://localhost:3000", exp, "sqli")
    missed = match_report(_report([]), "http://localhost:3000", exp, "sqli")
    # Found in 1 of 2 runs -> flaky -> reproducibility 0.
    score = score_case("x", "sqli", [found, missed])
    assert score.per_expected[0].found_in_runs == 1
    assert score.reproducibility == 0.0
    assert score.recall_best == 1.0  # ever found
    assert score.recall_mean == 0.5


def test_reproducibility_stable():
    exp = [_SQLI]
    m = match_report(_report([_finding(cwe="CWE-89")]), "http://localhost:3000", exp, "sqli")
    score = score_case("x", "sqli", [m, m])
    assert score.reproducibility == 1.0


# --- score_records (failed runs excluded) ---------------------------------------


def test_failed_runs_excluded_from_scoring():
    gts = {"juice-shop": GroundTruth(target="juice-shop", origin="http://localhost:3000",
                                     expected=(_SQLI,))}
    good = RunRecord(target="juice-shop", scan_type="sqli", origin="http://localhost:3000",
                     run_id="a", status="done", report=_report([_finding(cwe="CWE-89")]))
    failed = RunRecord(target="juice-shop", scan_type="sqli", origin="http://localhost:3000",
                       run_id="b", status="error", error="boom", report=None)
    scores, failures = score_records([good, failed], gts)
    assert len(scores) == 1
    assert scores[0].n_runs == 1  # only the successful run scored
    assert len(failures) == 1 and failures[0].run_id == "b"
