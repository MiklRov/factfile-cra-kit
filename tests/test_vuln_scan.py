"""
Tests for vuln_scan.py — Priority 2. No test in this file may make a real
network call to OSV.dev; `urllib.request.urlopen` (or the `osv_post` seam
one layer above it) is monkeypatched everywhere. The `no_network` autouse
fixture in conftest.py fails loudly if anything slips through unpatched.

Two levels are tested:
  - `_do_request` / `osv_post` / `osv_get` directly, via a fake
    `urllib.request.urlopen`, to pin down the retry/backoff branching
    (429/5xx retried, other 4xx not retried).
  - `query_vuln_ids`, via a monkeypatched `vuln_scan.osv_post` (the seam
    query_vuln_ids itself calls) — this is the natural boundary for
    exercising its own per-purl / per-batch logic without re-deriving
    _do_request's retry behaviour in every test.
"""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from factfile_cra_kit import vuln_scan


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

class FakeHTTPResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(code: int, body: bytes = b"") -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.osv.dev/x", code, "err", {}, io.BytesIO(body))


def mk_component(purl, name="lib", version="1.0.0", ecosystem="npm", direct=False, dev=False):
    return {
        "purl": purl, "name": name, "version": version,
        "ecosystem": ecosystem, "direct": direct, "dev": dev,
    }


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Retry backoff sleeps real seconds by default (1.5, 3, 6, 12...) —
    never let a test actually wait on them."""
    monkeypatch.setattr(vuln_scan.time, "sleep", lambda seconds: None)


# --------------------------------------------------------------------------
# purl_type / is_wellformed_purl
# --------------------------------------------------------------------------

def test_purl_type_wellformed():
    assert vuln_scan.purl_type("pkg:composer/foo/bar@1.0") == "composer"
    assert vuln_scan.purl_type("pkg:npm/left-pad@1.3.0") == "npm"


@pytest.mark.parametrize("bad", [None, "", "not-a-purl", "pkg:", "pkg:/nope"])
def test_purl_type_malformed(bad):
    assert vuln_scan.purl_type(bad) is None
    assert vuln_scan.is_wellformed_purl(bad) is False


# --------------------------------------------------------------------------
# extract_severity — four cases, four different correct outputs
# --------------------------------------------------------------------------

def test_extract_severity_ghsa_qualitative_label():
    detail = {"database_specific": {"severity": "HIGH"}}
    sev = vuln_scan.extract_severity(detail)
    assert sev == {"label": "HIGH", "rank": 3}


def test_extract_severity_ubuntu_label_in_score_field():
    detail = {"severity": [{"type": "Ubuntu", "score": "medium"}]}
    sev = vuln_scan.extract_severity(detail)
    assert sev == {"label": "medium", "rank": 2}


def test_extract_severity_bare_cvss_vector_no_qualitative_label():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    detail = {"severity": [{"type": "CVSS_V3", "score": vector}]}
    sev = vuln_scan.extract_severity(detail)
    assert sev["label"] is None
    assert sev["rank"] == 0
    assert sev["cvss"] == {"type": "CVSS_V3", "vector": vector}
    # the vector must be reported verbatim, never converted to a number
    assert "score" not in sev


def test_extract_severity_no_data_at_all():
    assert vuln_scan.extract_severity({}) is None
    assert vuln_scan.extract_severity({"severity": []}) is None
    assert vuln_scan.extract_severity({"database_specific": {}}) is None


# --------------------------------------------------------------------------
# _do_request retry/backoff branching
# --------------------------------------------------------------------------

def test_retry_on_429_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        if calls["n"] < 3:
            raise http_error(429)
        return FakeHTTPResponse(json.dumps({"ok": True}).encode())

    monkeypatch.setattr(vuln_scan.urllib.request, "urlopen", fake_urlopen)
    result = vuln_scan.osv_get("https://api.osv.dev/v1/vulns/TEST-1")
    assert result == {"ok": True}
    assert calls["n"] == 3


def test_retry_on_5xx_then_succeeds(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        if calls["n"] < 2:
            raise http_error(503)
        return FakeHTTPResponse(json.dumps({"ok": True}).encode())

    monkeypatch.setattr(vuln_scan.urllib.request, "urlopen", fake_urlopen)
    result = vuln_scan.osv_get("https://api.osv.dev/v1/vulns/TEST-2")
    assert result == {"ok": True}
    assert calls["n"] == 2


def test_429_exhausts_retries_and_raises(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        raise http_error(429)

    monkeypatch.setattr(vuln_scan.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(vuln_scan.OSVError):
        vuln_scan.osv_get("https://api.osv.dev/v1/vulns/TEST-3")
    assert calls["n"] == vuln_scan.MAX_RETRIES


def test_400_not_retried_fails_immediately(monkeypatch):
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        raise http_error(400, body=b"bad request")

    monkeypatch.setattr(vuln_scan.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(vuln_scan.OSVError) as exc_info:
        vuln_scan.osv_get("https://api.osv.dev/v1/vulns/TEST-4")
    assert calls["n"] == 1  # no retry for a plain 4xx
    assert "400" in str(exc_info.value)


# --------------------------------------------------------------------------
# query_vuln_ids — malformed purl, unsupported ecosystem, empty result,
# batch mismatch, well-formed purl with findings
# --------------------------------------------------------------------------

def test_wellformed_purl_with_findings_parsed_correctly(monkeypatch):
    comp = mk_component("pkg:npm/left-pad@1.3.0")

    def fake_osv_post(url, payload):
        return {"results": [{"vulns": [{"id": "OSV-2021-1234"}, {"id": "GHSA-xxxx-yyyy"}]}]}

    monkeypatch.setattr(vuln_scan, "osv_post", fake_osv_post)
    ids_by_purl, failures, truncated = vuln_scan.query_vuln_ids([comp])
    assert ids_by_purl == {"pkg:npm/left-pad@1.3.0": ["OSV-2021-1234", "GHSA-xxxx-yyyy"]}
    assert failures == []
    assert truncated == []


def test_malformed_purl_never_reaches_osv(monkeypatch):
    comp = mk_component("not-a-purl-at-all")

    def fail_if_called(url, payload):
        raise AssertionError("osv_post must not be called for a malformed purl")

    monkeypatch.setattr(vuln_scan, "osv_post", fail_if_called)
    ids_by_purl, failures, truncated = vuln_scan.query_vuln_ids([comp])
    assert ids_by_purl == {}
    assert len(failures) == 1
    assert failures[0]["purl"] == "not-a-purl-at-all"
    assert "malformed purl" in failures[0]["reason"]


def test_unsupported_ecosystem_with_empty_result_flagged_uncertain(monkeypatch):
    # "gradle" is explicitly not in KNOWN_PURL_TYPES (see vuln_scan module
    # docstring): gradle deps get "pkg:maven/..." purls, so an actual
    # "pkg:gradle/..." purl is a defensive/forward-compat case.
    comp = mk_component("pkg:gradle/com.example/foo@1.0", ecosystem="gradle")

    def fake_osv_post(url, payload):
        return {"results": [{}]}  # OSV: no "vulns" key at all

    monkeypatch.setattr(vuln_scan, "osv_post", fake_osv_post)
    ids_by_purl, failures, truncated = vuln_scan.query_vuln_ids([comp])
    assert ids_by_purl == {}
    assert len(failures) == 1
    assert "unsupported ecosystem" in failures[0]["reason"]


def test_known_type_genuinely_empty_result_is_not_a_failure(monkeypatch):
    comp = mk_component("pkg:npm/left-pad@1.3.0")

    def fake_osv_post(url, payload):
        return {"results": [{}]}

    monkeypatch.setattr(vuln_scan, "osv_post", fake_osv_post)
    ids_by_purl, failures, truncated = vuln_scan.query_vuln_ids([comp])
    assert ids_by_purl == {}
    assert failures == []  # a recognised ecosystem's clean result must not appear as a failure


def test_batch_length_mismatch_marks_whole_chunk_failed(monkeypatch):
    comps = [mk_component("pkg:npm/a@1.0.0"), mk_component("pkg:npm/b@2.0.0")]

    def fake_osv_post(url, payload):
        assert len(payload["queries"]) == 2
        return {"results": [{}]}  # only one result for two queries sent

    monkeypatch.setattr(vuln_scan, "osv_post", fake_osv_post)
    ids_by_purl, failures, truncated = vuln_scan.query_vuln_ids(comps)
    assert ids_by_purl == {}
    assert len(failures) == 2
    assert {f["purl"] for f in failures} == {"pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"}
    for f in failures:
        assert "could not be matched back to components" in f["reason"]


def test_osv_batch_network_error_fails_the_whole_chunk(monkeypatch):
    comps = [mk_component("pkg:npm/a@1.0.0")]

    def fake_osv_post(url, payload):
        raise vuln_scan.OSVError("network error: simulated")

    monkeypatch.setattr(vuln_scan, "osv_post", fake_osv_post)
    ids_by_purl, failures, truncated = vuln_scan.query_vuln_ids(comps)
    assert ids_by_purl == {}
    assert len(failures) == 1
    assert "OSV batch query failed" in failures[0]["reason"]


def test_truncated_results_surfaced_not_dropped(monkeypatch):
    comp = mk_component("pkg:npm/left-pad@1.3.0")

    def fake_osv_post(url, payload):
        return {"results": [{"vulns": [{"id": "OSV-1"}], "next_page_token": "abc"}]}

    monkeypatch.setattr(vuln_scan, "osv_post", fake_osv_post)
    ids_by_purl, failures, truncated = vuln_scan.query_vuln_ids([comp])
    assert truncated == ["pkg:npm/left-pad@1.3.0"]
    assert ids_by_purl == {"pkg:npm/left-pad@1.3.0": ["OSV-1"]}
