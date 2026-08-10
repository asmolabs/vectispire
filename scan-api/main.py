"""Zanshin Scan API — local HTTP backend for ScannerEngine (docs/architecture/01).

Runs Syft, Grype, gitleaks, and checkov directly as subprocesses (no nested
Docker) against paths on a filesystem *shared* with the Zanshin process —
see README.md for the deployment model.

This service holds no state of its own and talks to no database — it only
executes scanning tools and returns their JSON output.

**Security model.** Every endpoint takes a filesystem path and runs a scanner on
it, and `/scan/secrets` returns the secrets it finds *in the response body*. That
makes this service an arbitrary-file-read oracle unless two things hold, and both
are enforced here rather than left to the deployment:

1. **Every path must resolve inside the shared root** (`ZANSHIN_SHARED_ROOT`).
   Checking only that a path exists — which is what this service used to do —
   accepted `{"path": "/"}` and happily walked the whole filesystem.
2. **Every request must carry the shared token** (`ZANSHIN_SCAN_API_TOKEN`).
   Without a token configured the service refuses to serve anything: an
   unauthenticated scanner reachable on a network is worse than a broken one, so
   it fails closed instead of assuming nobody can reach it.
"""
import hmac
import json
import logging
import os
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("zanshin-scan-api")

# The only directory this service will read. Everything Zanshin asks about lives
# under the per-scan workspace it creates inside this root (see
# `ScannerEngine.get_workspace_root`).
SHARED_ROOT = os.path.realpath(os.getenv("ZANSHIN_SHARED_ROOT", "/shared"))

# Shared with the Zanshin side (`local_scan_api_token` setting). Absent = refuse.
AUTH_TOKEN = os.getenv("ZANSHIN_SCAN_API_TOKEN", "")

app = FastAPI(
    title="Zanshin Scan API",
    description=(
        "Sidecar scanning service for Zanshin (docs/architecture/01). Requires the "
        "shared token in `X-Zanshin-Token`, and only reads paths inside "
        "ZANSHIN_SHARED_ROOT."
    ),
)


def require_token(x_zanshin_token: str = Header(default="")) -> None:
    """Reject anything without the shared token.

    Fails closed when no token is configured: this service can read files and
    return secrets, so "nobody set a token" must not mean "anybody may ask".
    `compare_digest` keeps the comparison time independent of how many characters
    matched.
    """
    if not AUTH_TOKEN:
        logger.error("ZANSHIN_SCAN_API_TOKEN is not set — refusing every request")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Service non configuré : définissez ZANSHIN_SCAN_API_TOKEN (et la "
                "même valeur dans le réglage `local_scan_api_token` de Zanshin)."
            ),
        )
    if not x_zanshin_token or not hmac.compare_digest(x_zanshin_token, AUTH_TOKEN):
        logger.warning("Rejected a request with a missing or invalid token")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Jeton invalide.")


class ImageSbomRequest(BaseModel):
    image: str
    # Which architecture to audit the image as. Defaults to the value this
    # service used to hardcode, so an older Zanshin that doesn't send the field
    # keeps its previous behaviour.
    platform: str = "linux/amd64"


class DirectorySbomRequest(BaseModel):
    path: str


class SbomScanRequest(BaseModel):
    sbom: Dict[str, Any]


class SourceScanRequest(BaseModel):
    path: str


def run_cli(command: List[str]) -> subprocess.CompletedProcess:
    logger.info("Running: %s", " ".join(command))
    return subprocess.run(command, capture_output=True, text=True)


def resolve_shared_path(path: str) -> str:
    """The real path, or a refusal — never a path outside the shared root.

    `realpath` before comparing is what closes the symlink escape: a symlink
    inside the shared volume pointing at `/etc` would otherwise pass a naive
    prefix check. `commonpath` rather than `startswith` avoids the classic
    `/shared-evil` matching `/shared` mistake.
    """
    candidate = os.path.realpath(path)
    try:
        inside = os.path.commonpath([candidate, SHARED_ROOT]) == SHARED_ROOT
    except ValueError:
        # Different drives / relative vs absolute: not inside, by definition.
        inside = False
    if not inside:
        logger.warning("Refused a path outside the shared root: %r", path)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Chemin hors du répertoire partagé ({SHARED_ROOT}).",
        )
    if not os.path.exists(candidate):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Chemin introuvable : {path}. Ce service et Zanshin doivent partager "
                "le même volume, monté au même chemin des deux côtés — voir "
                "scan-api/README.md."
            ),
        )
    return candidate


@app.get("/health")
def health() -> Dict[str, Any]:
    """Unauthenticated liveness probe. Reveals nothing about the filesystem."""
    return {"status": "ok", "configured": bool(AUTH_TOKEN)}


@app.post("/sbom/image", dependencies=[Depends(require_token)])
def sbom_image(req: ImageSbomRequest) -> Dict[str, Any]:
    # `registry:` and not `docker:` — unlike the Docker backend, this service has
    # no Docker daemon to pull through (that is the reason it exists), so syft
    # must talk to the registry itself. A justified divergence, unlike the
    # platform, which used to be hardcoded here and ignored the operator's
    # setting.
    result = run_cli(["syft", f"registry:{req.image}", "--platform", req.platform, "-o", "json"])
    if result.returncode != 0:
        raise HTTPException(status_code=502, detail=f"syft failed: {result.stderr[-2000:]}")
    return json.loads(result.stdout)


@app.post("/sbom/directory", dependencies=[Depends(require_token)])
def sbom_directory(req: DirectorySbomRequest) -> Dict[str, Any]:
    path = resolve_shared_path(req.path)
    result = run_cli(["syft", f"dir:{path}", "-o", "json"])
    if result.returncode != 0:
        raise HTTPException(status_code=502, detail=f"syft failed: {result.stderr[-2000:]}")
    return json.loads(result.stdout)


@app.post("/scan/vulnerabilities", dependencies=[Depends(require_token)])
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


@app.post("/scan/secrets", dependencies=[Depends(require_token)])
def scan_secrets(req: SourceScanRequest) -> List[Dict[str, Any]]:
    path = resolve_shared_path(req.path)

    # The report goes to this service's own scratch space, never inside
    # `req.path`: it is read back here and returned as JSON, so it never
    # needs to exist on the shared volume — and writing it into the scanned
    # directory would drop a file containing every detected secret in
    # cleartext into the tree the rest of the pipeline then walks (see
    # SOURCE_SUBDIR in zanshin/services/scan_processor.py).
    fd, report_path = tempfile.mkstemp(suffix=".json", prefix="zanshin-gitleaks-")
    os.close(fd)
    try:
        result = run_cli([
            "gitleaks", "detect",
            f"--source={path}",
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
    finally:
        if os.path.exists(report_path):
            os.remove(report_path)


@app.post("/scan/iac", dependencies=[Depends(require_token)])
def scan_iac(req: SourceScanRequest) -> List[Dict[str, Any]]:
    path = resolve_shared_path(req.path)

    result = run_cli(["checkov", "-d", path, "-o", "json", "--soft-fail", "--compact"])
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail=f"checkov output not parseable: {result.stderr[-2000:]}")

    reports = payload if isinstance(payload, list) else [payload]
    failed_checks: List[Dict[str, Any]] = []
    for report in reports:
        failed_checks.extend((report.get("results") or {}).get("failed_checks", []))
    return failed_checks
