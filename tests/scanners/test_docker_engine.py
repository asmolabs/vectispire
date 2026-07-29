import json
import os
import tempfile

import pytest

from zanshin.services.scanners.docker_engine import DockerScannerEngine


class FakeContainers:
    def __init__(self, output=b""):
        self.output = output
        self.calls = []

    def run(self, **kwargs):
        self.calls.append(kwargs)
        return self.output


class FakeClient:
    def __init__(self, output=b""):
        self.containers = FakeContainers(output)


@pytest.fixture()
def engine():
    return DockerScannerEngine()


def test_generate_sbom_for_image_parses_syft_json(engine):
    payload = {"artifacts": [{"name": "foo"}]}
    fake_client = FakeClient(json.dumps(payload).encode("utf-8"))
    engine._docker_client = lambda: fake_client

    result = engine.generate_sbom_for_image("nginx:latest")

    assert result == payload
    command = fake_client.containers.calls[0]["command"]
    assert command[0] == "registry:nginx:latest"


def test_generate_sbom_for_directory_parses_syft_json(engine, tmp_path):
    payload = {"artifacts": []}
    fake_client = FakeClient(json.dumps(payload).encode("utf-8"))
    engine._docker_client = lambda: fake_client

    result = engine.generate_sbom_for_directory(str(tmp_path), "sub/dir")

    assert result == payload
    command = fake_client.containers.calls[0]["command"]
    assert command[0] == "dir:/src/sub/dir"


def test_scan_sbom_writes_sbom_file_and_parses_grype_json(engine, tmp_path):
    payload = {"matches": [{"vulnerability": {"id": "CVE-1"}}]}
    fake_client = FakeClient(json.dumps(payload).encode("utf-8"))
    engine._docker_client = lambda: fake_client

    result = engine.scan_sbom(str(tmp_path), {"artifacts": []})

    assert result == payload
    assert os.path.exists(os.path.join(tmp_path, "sbom.json"))


def test_scan_secrets_reads_gitleaks_report_file(engine, tmp_path):
    report = [{"RuleID": "aws-access-token", "File": "config.py"}]

    def fake_run(**kwargs):
        report_path = os.path.join(str(tmp_path), engine.GITLEAKS_REPORT_FILENAME)
        with open(report_path, "w") as f:
            json.dump(report, f)
        return b""

    fake_client = FakeClient()
    fake_client.containers.run = fake_run
    engine._docker_client = lambda: fake_client

    result = engine.scan_secrets(str(tmp_path))

    assert result == report


def test_scan_secrets_returns_empty_list_when_no_report_file(engine, tmp_path):
    engine._docker_client = lambda: FakeClient()
    assert engine.scan_secrets(str(tmp_path)) == []


def test_scan_secrets_returns_empty_list_when_report_file_is_empty(engine, tmp_path):
    def fake_run(**kwargs):
        report_path = os.path.join(str(tmp_path), engine.GITLEAKS_REPORT_FILENAME)
        with open(report_path, "w") as f:
            f.write("")
        return b""

    fake_client = FakeClient()
    fake_client.containers.run = fake_run
    engine._docker_client = lambda: fake_client

    assert engine.scan_secrets(str(tmp_path)) == []


def test_scan_iac_handles_dict_shaped_checkov_output(engine, tmp_path):
    payload = json.dumps({
        "results": {
            "failed_checks": [
                {"check_id": "CKV_AWS_20", "resource": "aws_s3_bucket.foo", "file_path": "/main.tf", "severity": "HIGH"},
            ]
        }
    })
    engine._docker_client = lambda: FakeClient(payload.encode("utf-8"))

    result = engine.scan_iac(str(tmp_path))

    assert len(result) == 1
    assert result[0]["check_id"] == "CKV_AWS_20"


def test_scan_iac_handles_list_shaped_checkov_output_multiple_frameworks(engine, tmp_path):
    payload = json.dumps([
        {"results": {"failed_checks": [{"check_id": "CKV_K8S_1"}]}},
        {"results": {"failed_checks": [{"check_id": "CKV_AWS_99"}]}},
    ])
    engine._docker_client = lambda: FakeClient(payload.encode("utf-8"))

    result = engine.scan_iac(str(tmp_path))

    assert {c["check_id"] for c in result} == {"CKV_K8S_1", "CKV_AWS_99"}


def test_scan_iac_returns_empty_list_on_malformed_output(engine, tmp_path):
    engine._docker_client = lambda: FakeClient(b"not valid json {{{")

    assert engine.scan_iac(str(tmp_path)) == []
