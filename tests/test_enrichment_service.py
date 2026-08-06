import pytest

from zanshin.models.finding import Finding
from zanshin.services.enrichment_service import (
    EnrichmentService,
    EPSS_API_URL,
    KEV_CATALOG_URL,
    SETTING_KEY_ENRICHMENT_ENABLED,
)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def reset_class_level_kev_cache():
    """`EnrichmentService` caches the KEV catalog at the *class* level on
    purpose (see its docstring — the service is recreated on every request
    in the real app). That means tests would otherwise leak cache state
    into each other depending on execution order; reset it before/after
    every test in this file."""
    EnrichmentService._kev_cache = set()
    EnrichmentService._kev_cache_fetched_at = 0.0
    yield
    EnrichmentService._kev_cache = set()
    EnrichmentService._kev_cache_fetched_at = 0.0


def make_fake_http_get(epss_data=None, kev_cves=None, calls=None):
    epss_data = epss_data or []
    kev_cves = kev_cves or []
    calls = calls if calls is not None else []

    def fake_http_get(url, **kwargs):
        calls.append((url, kwargs))
        if url == EPSS_API_URL:
            requested = kwargs["params"]["cve"].split(",")
            return FakeResponse({"data": [d for d in epss_data if d["cve"] in requested]})
        if url == KEV_CATALOG_URL:
            return FakeResponse({"vulnerabilities": [{"cveID": c} for c in kev_cves]})
        raise AssertionError(f"unexpected url {url}")

    return fake_http_get, calls


def test_enrich_findings_populates_epss_and_kev(settings_service):
    calls = []
    fake_get, calls = make_fake_http_get(
        epss_data=[
            {"cve": "CVE-2021-44228", "epss": "0.94520"},
            {"cve": "CVE-2024-9999", "epss": "0.001"},
        ],
        kev_cves=["CVE-2021-44228"],
        calls=calls,
    )
    svc = EnrichmentService(settings_service, http_get=fake_get)

    critical = Finding(scan_id=1, type="vulnerability", identifier="CVE-2021-44228", is_kev=False)
    low = Finding(scan_id=1, type="vulnerability", identifier="CVE-2024-9999", is_kev=False)
    # `is_kev` is set explicitly here (rather than relying on the column's
    # `default=False`): SQLAlchemy only applies column defaults on flush to
    # a real session, and these Finding objects are plain in-memory objects
    # in this test, never persisted through `FakeDb`.
    secret = Finding(scan_id=1, type="secret", identifier="aws-key", is_kev=False)

    class FakeDb:
        def commit(self):
            pass

    svc.enrich_findings(FakeDb(), [critical, low, secret])

    assert critical.epss_score == 0.94520
    assert critical.is_kev is True
    assert low.epss_score == 0.001
    assert low.is_kev is False
    # Only vulnerability-type findings are touched.
    assert secret.epss_score is None
    assert secret.is_kev is False


def test_enrich_findings_short_circuits_when_disabled(settings_service):
    settings_service.update_setting(SETTING_KEY_ENRICHMENT_ENABLED, "false")
    fake_get, calls = make_fake_http_get()
    svc = EnrichmentService(settings_service, http_get=fake_get)

    finding = Finding(scan_id=1, type="vulnerability", identifier="CVE-2021-44228")

    class FakeDb:
        def commit(self):
            pass

    svc.enrich_findings(FakeDb(), [finding])

    assert finding.epss_score is None
    assert calls == []


def test_enrich_findings_survives_network_failure(settings_service):
    def broken_http_get(url, **kwargs):
        raise ConnectionError("network is down (simulated)")

    svc = EnrichmentService(settings_service, http_get=broken_http_get)
    finding = Finding(scan_id=1, type="vulnerability", identifier="CVE-XXXX-0001", is_kev=False)

    class FakeDb:
        def commit(self):
            pass

    # Must not raise, despite every HTTP call failing.
    svc.enrich_findings(FakeDb(), [finding])

    assert finding.epss_score is None
    assert finding.is_kev is False


def test_kev_catalog_is_cached_across_instances(settings_service):
    calls = []
    fake_get, calls = make_fake_http_get(kev_cves=["CVE-2021-44228"], calls=calls)

    class FakeDb:
        def commit(self):
            pass

    finding_a = Finding(scan_id=1, type="vulnerability", identifier="CVE-2021-44228")
    EnrichmentService(settings_service, http_get=fake_get).enrich_findings(FakeDb(), [finding_a])

    calls.clear()
    finding_b = Finding(scan_id=2, type="vulnerability", identifier="CVE-2021-44228")
    EnrichmentService(settings_service, http_get=fake_get).enrich_findings(FakeDb(), [finding_b])

    kev_calls = [c for c in calls if c[0] == KEV_CATALOG_URL]
    assert kev_calls == [], "KEV catalog should be reused from the class-level cache, not refetched"
    assert finding_b.is_kev is True


def test_enrich_findings_with_no_vulnerability_findings_makes_no_calls(settings_service):
    fake_get, calls = make_fake_http_get()
    svc = EnrichmentService(settings_service, http_get=fake_get)

    class FakeDb:
        def commit(self):
            pass

    secret_only = Finding(scan_id=1, type="secret", identifier="aws-key")
    svc.enrich_findings(FakeDb(), [secret_only])

    assert calls == []
