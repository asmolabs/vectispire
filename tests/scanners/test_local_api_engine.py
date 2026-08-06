from zanshin.services.scanners.local_api_engine import LocalApiScannerEngine


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def make_engine(calls):
    def fake_post(url, json=None, timeout=None, headers=None):
        calls.append((url, json))
        if url.endswith("/sbom/directory") or url.endswith("/sbom/image"):
            return FakeResponse({"artifacts": [{"name": "foo"}]})
        if url.endswith("/scan/vulnerabilities"):
            return FakeResponse({"matches": []})
        if url.endswith("/scan/secrets") or url.endswith("/scan/iac"):
            return FakeResponse([])
        raise AssertionError(f"unexpected url {url}")

    return LocalApiScannerEngine(
        base_url="http://scan-api:8686/",
        shared_workspace_root="/shared/zanshin",
        http_post=fake_post,
    )


def test_base_url_trailing_slash_is_stripped():
    calls = []
    engine = make_engine(calls)
    engine.generate_sbom_for_image("nginx:latest")
    assert calls[0][0] == "http://scan-api:8686/sbom/image"


def test_get_workspace_root_returns_configured_shared_dir():
    engine = make_engine([])
    assert engine.get_workspace_root() == "/shared/zanshin"


def test_get_workspace_root_none_when_not_configured():
    engine = LocalApiScannerEngine(base_url="http://x", shared_workspace_root="", http_post=lambda *a, **k: None)
    assert engine.get_workspace_root() is None


def test_generate_sbom_for_directory_joins_sub_path():
    calls = []
    engine = make_engine(calls)

    engine.generate_sbom_for_directory("/shared/zanshin/scan_1", "src")

    assert calls[-1] == ("http://scan-api:8686/sbom/directory", {"path": "/shared/zanshin/scan_1/src"})


def test_generate_sbom_for_directory_without_sub_path():
    calls = []
    engine = make_engine(calls)

    engine.generate_sbom_for_directory("/shared/zanshin/scan_1", "")

    assert calls[-1] == ("http://scan-api:8686/sbom/directory", {"path": "/shared/zanshin/scan_1"})


def test_scan_sbom_sends_sbom_in_body_not_as_a_path():
    calls = []
    engine = make_engine(calls)
    sbom = {"artifacts": [{"name": "foo"}]}

    engine.scan_sbom("/shared/zanshin/scan_1", sbom)

    assert calls[-1] == ("http://scan-api:8686/scan/vulnerabilities", {"sbom": sbom})


def test_scan_secrets_and_scan_iac_use_target_path():
    calls = []
    engine = make_engine(calls)

    engine.scan_secrets("/shared/zanshin/scan_1", "")
    engine.scan_iac("/shared/zanshin/scan_1", "infra")

    assert calls[0] == ("http://scan-api:8686/scan/secrets", {"path": "/shared/zanshin/scan_1"})
    assert calls[1] == ("http://scan-api:8686/scan/iac", {"path": "/shared/zanshin/scan_1/infra"})
