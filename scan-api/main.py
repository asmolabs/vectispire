"""Zanshin Scan API — local HTTP backend for ScannerEngine (ADR-001, Phase 4).

Runs Syft, Grype, gitleaks, and checkov directly as subprocesses (no nested
Docker) against paths on a filesystem *shared* with the Zanshin process —
see README.md for the deployment model. Every CLI invocation here mirrors
`zanshin/services/scanners/docker_engine.py` exactly, minus the `docker run`
wrapper, so behavior should match the Docker backend for the same inputs.

This service holds no state of its own and talks to no database — it only
executes scanning tools and returns their JSON output.
"""
import json
import logging
import os
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("zanshin-scan-api")

app = FastAPI(
    title="Zanshin Scan API",
    description=(
        "Sidecar scanning service for Zanshin (ADR-001 Phase 4). "
        "Not exposed to the internet: intended to be reachable only from "
        "the Zanshin process it shares a volume with."
    ),
)

GITLEAKS_REPORT_FILENAME = "zanshin-gitleaks-report.json"


class ImageSbomRequest(BaseModel):
    image: str


class DirectorySbomRequest(BaseModel):
    path: str


class SbomScanRequest(BaseModel):
    sbom: Dict[str, Any]


class SourceScanRequest(BaseModel):
    path: str


def run_cli(command: List[str]) -> subprocess.CompletedProcess:
    logger.info("Running: %s", " ".join(command))
    return subprocess.run(command, capture_output=True, text=True)


def require_shared_path(path: str) -> None:
    """Every request references a path that must already exist on the
    volume shared with Zanshin — if it doesn't, the volume mount is
    probably misconfigured (see README.md), not a scan-time error."""
    if not os.path.exists(path):
        raise HTTPException(
            status_code=404,
            detail=(
                f"Path not found: {path}. This service and Zanshin must "
                "share the same volume, mounted at the same path on both "
                "sides — see scan-api/README.md."
            ),
        )


@app.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/sbom/image")
def sbom_image(req: ImageSbomRequest) -> Dict[str, Any]:
    result = run_cli(["syft", f"registry:{req.image}", "--platform", "linux/amd64", "-o", "json"])
    if result.returncode != 0:
        raise HTTPException(status_code=502, detail=f"syft failed: {result.stderr[-2000:]}")
    return json.loads(result.stdout)


@app.post("/sbom/directory")
def sbom_directory(req: DirectorySbomRequest) -> Dict[str, Any]:
    require_shared_path(req.path)
    result = run_cli(["syft", f"dir:{req.path}", "-o", "json"])
    if result.returncode != 0:
        raise HTTPException(status_code=502, detail=f"syft failed: {result.stderr[-2000:]}")
    return json.loads(result.stdout)


@app.post("/scan/vulnerabilities")
def scan_vulnerabilities(req: SbomScanRequest) -> Dict[str, Any]:
    # The SBOM arrives in the request body, not as a shared path (see
    # LocalApiScannerEngine.scan_sbom) — write it to this service's own
    # scratch space, not the shared volume, since it's only needed within
    # this one request.
    fd, sbom_path = tempfile.mkstemp(suffix=".json", prefix="zanshin-sbom-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(req.sbom, f)
        result = run_cli(["grype", f"sbom:{sbom_path}", "-o", "json"])
        if result.returncode != 0:
            raise HTTPException(status_code=502, detail=f"grype failed: {result.stderr[-2000:]}")
        return json.loads(result.stdout)
    finally:
        if os.path.exists(sbom_path):
            os.remove(sbom_path)


@app.post("/scan/secrets")
def scan_secrets(req: SourceScanRequest) -> List[Dict[str, Any]]:
    require_shared_path(req.path)
    report_path = os.path.join(req.path, GITLEAKS_REPORT_FILENAME)

    result = run_cli([
        "gitleaks", "detect",
        f"--source={req.path}",
        "--no-git",
        "--report-format=json",
        f"--report-path={report_path}",
        "--exit-code=0",
    ])
    if result.returncode != 0:
        raise HTTPException(status_code=502, detail=f"gitleaks failed: {result.stderr[-2000:]}")

    if not os.path.exists(report_path):
        return []
    with open(report_path) as f:
        content = f.read().strip()
    return json.loads(content) if content else []


@app.post("/scan/iac")
def scan_iac(req: SourceScanRequest) -> List[Dict[str, Any]]:
    require_shared_path(req.path)

    result = run_cli(["checkov", "-d", req.path, "-o", "json", "--soft-fail", "--compact"])
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail=f"checkov output not parseable: {result.stderr[-2000:]}")

    reports = payload if isinstance(payload, list) else [payload]
    failed_checks: List[Dict[str, Any]] = []
    for report in reports:
        failed_checks.extend((report.get("results") or {}).get("failed_checks", []))
    return failed_checks
