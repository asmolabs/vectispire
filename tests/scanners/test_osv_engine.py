from zanshin.services.scanners.osv_engine import OsvScannerEngine


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


class FakeLocalEngine:
    def __init__(self):
        self.calls = []

    def generate_sbom_for_image(self, image_string):
        self.calls.append(("image", image_string))
        return {"artifacts": []}

    def generate_sbom_for_directory(self, work_dir, sub_path):
        self.calls.append(("directory", work_dir, sub_path))
        return {"artifacts": []}

    def scan_secrets(self, work_dir, sub_path=""):
        self.calls.append(("secrets", work_dir, sub_path))
        return ["sentinel-secrets"]

    def scan_iac(self, work_dir, sub_path=""):
        self.calls.append(("iac", work_dir, sub_path))
        return ["sentinel-iac"]


def test_sbom_generation_and_secrets_and_iac_are_delegated_to_local_engine():
    local = FakeLocalEngine()
    engine = OsvScannerEngine(local_engine=local, http_post=lambda *a, **k: FakeResponse({}))

    assert engine.generate_sbom_for_image("nginx:latest") == {"artifacts": []}
    assert engine.generate_sbom_for_directory("/work", "sub") == {"artifacts": []}
    assert engine.scan_secrets("/work", "sub") == ["sentinel-secrets"]
    assert engine.scan_iac("/work", "sub") == ["sentinel-iac"]
    assert ("image", "nginx:latest") in local.calls
    assert ("directory", "/work", "sub") in local.calls


def test_scan_sbom_translates_osv_response_to_grype_shape():
    def fake_post(url, **kwargs):
        purl = kwargs["json"]["package"]["purl"]
        if "log4j-core" in purl:
            return FakeResponse({"vulns": [{
                "id": "GHSA-jfh8-c2jp-5v3q",
                "aliases": ["CVE-2021-44228"],
                "summary": "Remote code execution in Log4j2",
                "database_specific": {"severity": "CRITICAL"},
                "references": [{"type": "ADVISORY", "url": "https://example.com/advisory"}],
            }]})
        return FakeResponse({"vulns": []})

    engine = OsvScannerEngine(local_engine=FakeLocalEngine(), http_post=fake_post)
    sbom = {
        "artifacts": [
            {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/x/log4j-core@2.14.1", "locations": [{"path": "/app/lib/log4j-core.jar"}]},
            {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0", "locations": []},
            {"name": "no-purl-pkg", "version": "1.0.0"},
        ]
    }

    result = engine.scan_sbom("/work", sbom)

    assert result["engine_source"] == "osv"
    assert len(result["matches"]) == 1
    match = result["matches"][0]
    assert match["vulnerability"]["id"] == "CVE-2021-44228"
    assert match["vulnerability"]["severity"] == "critical"
    assert match["artifact"]["name"] == "log4j-core"


def test_scan_sbom_skips_artifacts_without_a_purl():
    calls = []

    def fake_post(url, **kwargs):
        calls.append(kwargs["json"]["package"]["purl"])
        return FakeResponse({"vulns": []})

    engine = OsvScannerEngine(local_engine=FakeLocalEngine(), http_post=fake_post)
    sbom = {"artifacts": [{"name": "no-purl"}, {"name": "has-purl", "purl": "pkg:pypi/has-purl@1.0"}]}

    engine.scan_sbom("/work", sbom)

    assert calls == ["pkg:pypi/has-purl@1.0"]


def test_scan_sbom_resilient_to_a_single_package_lookup_failure():
    def fake_post(url, **kwargs):
        raise ConnectionError("simulated network failure")

    engine = OsvScannerEngine(local_engine=FakeLocalEngine(), http_post=fake_post)
    sbom = {"artifacts": [{"name": "foo", "purl": "pkg:pypi/foo@1.0"}]}

    result = engine.scan_sbom("/work", sbom)

    assert result == {"matches": [], "engine_source": "osv"}


def test_severity_falls_back_to_unknown_when_not_classified():
    def fake_post(url, **kwargs):
        return FakeResponse({"vulns": [{"id": "OSV-1", "aliases": []}]})

    engine = OsvScannerEngine(local_engine=FakeLocalEngine(), http_post=fake_post)
    sbom = {"artifacts": [{"name": "foo", "purl": "pkg:pypi/foo@1.0"}]}

    result = engine.scan_sbom("/work", sbom)

    assert result["matches"][0]["vulnerability"]["severity"] == "unknown"
    assert result["matches"][0]["vulnerability"]["id"] == "OSV-1"  # falls back to OSV id, no CVE alias
