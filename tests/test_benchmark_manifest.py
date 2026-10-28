"""Ground-truth manifest schema + the real Juice Shop manifest.

The schema rules matter because scoring trusts them: a scored weakness with no oracle would
let the benchmark fall back on the agent's own claim, so the loader refuses it.
"""

from pathlib import Path

import pytest

from safetywebbing.benchmark.manifest import ManifestError, load_manifest, load_manifests

TARGETS_DIR = Path(__file__).resolve().parents[1] / "benchmark" / "targets"

_HEADER = 'target = "{target}"\nconfig = "{config}"\nreference = "test"\n'
_GOOD_VULN = """
[[vuln]]
id = "v-1"
title = "t"
scan_type = "sqli"
cwe = "CWE-89"
endpoints = [{ method = "get", path = "/x", param = "q" }]
oracles = [{ kind = "trace_match", response_pattern = "boom" }]
"""


def _write(tmp_path, body, *, target="dvwa", config="low", name="m.toml"):
    path = tmp_path / name
    path.write_text(_HEADER.format(target=target, config=config) + body, encoding="utf-8")
    return path


# --- the real Juice Shop manifest ---------------------------------------------


def test_juice_shop_manifest_loads():
    m = load_manifest(TARGETS_DIR / "juice-shop.toml")
    assert (m.target, m.config) == ("juice-shop", "default")
    assert "717f5ef" in m.reference  # the build the keys were checked against


def test_juice_shop_scored_entries_all_have_an_oracle():
    m = load_manifest(TARGETS_DIR / "juice-shop.toml")
    assert m.scored()
    assert all(v.oracles for v in m.scored())


def test_juice_shop_scan_type_expectations():
    m = load_manifest(TARGETS_DIR / "juice-shop.toml")
    sqli = {v.id for v in m.expected_for("sqli")}
    assert sqli == {"js-sqli-login-admin", "js-sqli-search-union", "js-sqli-search-schema"}
    # DOM XSS runs in the browser: listed, but never counted against an HTTP-only agent.
    xss = {v.id for v in m.expected_for("xss")}
    assert "js-xss-dom-search" not in xss
    assert "js-xss-reflected-track-order" in xss
    assert "js-xss-dom-search" in {v.id for v in m.vulns}
    # A general scan is asked about everything scored, including what no narrower goal covers.
    general = {v.id for v in m.expected_for("general")}
    assert {"js-exposure-ftp-confidential", "js-nosqli-track-order"} <= general
    assert general == {v.id for v in m.scored()}


def test_juice_shop_shared_root_causes_are_grouped():
    m = load_manifest(TARGETS_DIR / "juice-shop.toml")
    by_sink: dict[str, list[str]] = {}
    for v in m.vulns:
        if v.sink:
            by_sink.setdefault(v.sink, []).append(v.id)
    assert sorted(by_sink["search-sql"]) == ["js-sqli-search-schema", "js-sqli-search-union"]


def test_juice_shop_xss_entries_have_a_fallback_oracle():
    """Juice Shop's own check needs one exact payload; the trace oracle covers any other."""
    m = load_manifest(TARGETS_DIR / "juice-shop.toml")
    for v in m.expected_for("xss"):
        kinds = {o.kind for o in v.oracles}
        assert kinds == {"juice_challenge", "trace_match"}, v.id


def test_load_manifests_keys_by_target_and_config():
    manifests = load_manifests(TARGETS_DIR)
    assert ("juice-shop", "default") in manifests


# --- schema rules -------------------------------------------------------------


def test_minimal_valid_manifest(tmp_path):
    m = load_manifest(_write(tmp_path, _GOOD_VULN))
    assert m.vulns[0].endpoints[0].method == "GET"  # normalised to upper case
    assert [v.id for v in m.expected_for("sqli")] == ["v-1"]
    assert m.expected_for("xss") == []


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (('scan_type = "sqli"', 'scan_type = "rce"'), "unknown scan_type"),
        (('cwe = "CWE-89"', 'cwe = "89"'), "cwe must look like"),
        (('id = "v-1"', 'id = "V 1"'), "id must be lowercase"),
        (('path = "/x"', 'path = "x"'), "must start with"),
        (('method = "get"', 'method = "FETCH"'), "unknown HTTP method"),
        (('response_pattern = "boom"', 'response_pattern = "("'), "invalid regex"),
        (('response_pattern = "boom"', 'request_pattern = ""'), "needs a request_pattern"),
        (('oracles = [{ kind = "trace_match", response_pattern = "boom" }]', ""), "needs at least one oracle"),
        (('kind = "trace_match"', 'kind = "magic"'), "kind"),
    ],
)
def test_invalid_entries_are_rejected(tmp_path, edit, message):
    old, new = edit
    assert old in _GOOD_VULN
    path = _write(tmp_path, _GOOD_VULN.replace(old, new))
    with pytest.raises(ManifestError, match=message):
        load_manifest(path)


def test_error_names_the_file(tmp_path):
    path = _write(tmp_path, _GOOD_VULN.replace("CWE-89", "nope"), name="bad-one.toml")
    with pytest.raises(ManifestError, match="bad-one.toml"):
        load_manifest(path)


def test_unparsable_toml_is_a_manifest_error(tmp_path):
    path = tmp_path / "broken.toml"
    path.write_text("this is = = not toml", encoding="utf-8")
    with pytest.raises(ManifestError, match="broken.toml"):
        load_manifest(path)


def test_duplicate_ids_rejected(tmp_path):
    with pytest.raises(ManifestError, match="duplicate vuln id"):
        load_manifest(_write(tmp_path, _GOOD_VULN + _GOOD_VULN))


def test_juice_oracle_only_for_juice_shop(tmp_path):
    body = _GOOD_VULN.replace(
        'oracles = [{ kind = "trace_match", response_pattern = "boom" }]',
        'oracles = [{ kind = "juice_challenge", key = "loginAdminChallenge" }]',
    )
    with pytest.raises(ManifestError, match="only apply to juice-shop"):
        load_manifest(_write(tmp_path, body, target="dvwa"))
    assert load_manifest(_write(tmp_path, body, target="juice-shop", config="default"))


def test_safe_control_must_have_no_oracle_and_be_scored(tmp_path):
    control = _GOOD_VULN.replace('cwe = "CWE-89"', 'cwe = "CWE-89"\nexpect = "safe"')
    with pytest.raises(ManifestError, match="nothing to exploit"):
        load_manifest(_write(tmp_path, control))
    no_oracle = control.replace('oracles = [{ kind = "trace_match", response_pattern = "boom" }]', "")
    m = load_manifest(_write(tmp_path, no_oracle))
    assert [v.id for v in m.controls()] == ["v-1"]
    assert m.scored() == []  # controls measure false positives, not recall
    unscored = no_oracle.replace('cwe = "CWE-89"', 'cwe = "CWE-89"\nscoring = "out_of_scope"')
    with pytest.raises(ManifestError, match="must be scored"):
        load_manifest(_write(tmp_path, unscored))


def test_unscored_vulnerable_entry_needs_no_oracle(tmp_path):
    body = _GOOD_VULN.replace('cwe = "CWE-89"', 'cwe = "CWE-89"\nscoring = "out_of_capability"').replace(
        'oracles = [{ kind = "trace_match", response_pattern = "boom" }]', ""
    )
    m = load_manifest(_write(tmp_path, body))
    assert m.scored() == []


def test_expected_for_rejects_unknown_scan_type(tmp_path):
    m = load_manifest(_write(tmp_path, _GOOD_VULN))
    with pytest.raises(ValueError, match="unknown scan_type"):
        m.expected_for("nope")


def test_duplicate_target_config_across_files(tmp_path):
    _write(tmp_path, _GOOD_VULN, name="a.toml")
    _write(tmp_path, _GOOD_VULN, name="b.toml")
    with pytest.raises(ManifestError, match="duplicate manifest"):
        load_manifests(tmp_path)


# --- file_oracle and accepted_weakness (self-reporting targets) -----------------

_FILE_VULN = _GOOD_VULN.replace(
    'oracles = [{ kind = "trace_match", response_pattern = "boom" }]',
    'oracles = [{ kind = "file_oracle", key = "V01" }, { kind = "trace_match", response_pattern = "boom" }]',
)
_ACCEPTED = """
[[accepted_weakness]]
id = "no-https"
title = "Plain HTTP"
cwe = "CWE-319"
reason = "loopback only"
"""


def test_file_oracle_loads_for_vulnshop(tmp_path):
    m = load_manifest(_write(tmp_path, _FILE_VULN + _ACCEPTED, target="vulnshop", config="default"))
    assert [o.kind for o in m.vulns[0].oracles] == ["file_oracle", "trace_match"]
    assert [w.id for w in m.accepted_weaknesses] == ["no-https"]


def test_file_oracle_refused_for_other_targets(tmp_path):
    with pytest.raises(ManifestError, match="file_oracle oracles only apply to vulnshop"):
        load_manifest(_write(tmp_path, _FILE_VULN, target="dvwa", config="low"))


@pytest.mark.parametrize(
    "bad", ['key = "V 01"', 'key = "1"'],
)
def test_file_oracle_key_must_be_an_identifier(tmp_path, bad):
    body = _FILE_VULN.replace('key = "V01"', bad)
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, body, target="vulnshop", config="default"))


def test_accepted_weakness_needs_a_reason_and_unique_id(tmp_path):
    no_reason = _ACCEPTED.replace('reason = "loopback only"', 'reason = ""')
    with pytest.raises(ManifestError):
        load_manifest(_write(tmp_path, _FILE_VULN + no_reason, target="vulnshop", config="default"))
    with pytest.raises(ManifestError, match="duplicate id"):
        load_manifest(_write(tmp_path, _FILE_VULN + _ACCEPTED + _ACCEPTED, target="vulnshop", config="default"))
