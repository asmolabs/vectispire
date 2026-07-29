# Zanshin Scan API

Sidecar HTTP service implementing the `local_api` scan backend described in
[ADR-001](../docs/architecture/ADR-001-scanner-backends.md), Phase 4.

It runs Syft, Grype, gitleaks, and checkov **directly** (as subprocesses,
not nested Docker containers) and exposes them over a small HTTP API that
Zanshin's `LocalApiScannerEngine` calls into. Every command it runs mirrors
`zanshin/services/scanners/docker_engine.py` exactly, minus the `docker run`
wrapper.

## Why this exists

The default `docker` backend has Zanshin's own process spin up a Docker
container per scanning step, which requires Docker socket access from
wherever Zanshin runs. This service moves that requirement here instead:
Zanshin talks to it over plain HTTP and needs no Docker access itself.

## Deployment model: same host, shared volume

This implementation assumes `scan-api` runs **on the same host as
Zanshin**, with both processes mounting the **same directory at the same
path**. Zanshin only ever sends this service plain filesystem paths (never
file uploads) — e.g. it tells `scan-api` "generate an SBOM for
`/shared/zanshin-scans/scan_42`", and `scan-api` reads that directory
directly. If the paths don't resolve to the same files on both sides,
every call will fail with a 404.

A fully decoupled model (this service running on a different machine, with
Zanshin uploading file contents over HTTP) was considered but not built —
it needs streaming multipart uploads for potentially large checkouts/images
and could not be exercised in the environment that wrote this code (no
Docker or external network access there). If you need that later, the
integration point is `LocalApiScannerEngine` on the Zanshin side and the
`path`-based request bodies here.

Example `docker-compose.yml` sketch (adapt to however Zanshin itself is
actually deployed — this repo doesn't have one today):

```yaml
services:
  zanshin:
    build: .
    environment:
      # picked up by zanshin/services/scanners/factory.py via the
      # `setting` table, not directly as env vars — set these from the
      # Paramètres page instead, this is just to show the shared mount.
      - ...
    volumes:
      - scan-workspace:/shared/zanshin-scans

  scan-api:
    build: ./scan-api
    ports:
      - "8686:8686"   # bind to an internal network only, see Security below
    volumes:
      - scan-workspace:/shared/zanshin-scans

volumes:
  scan-workspace:
```

## Configuring Zanshin to use it

In Zanshin's **Paramètres** page (or directly in the `setting` table):

- `scan_backend` = `local_api`
- `local_scan_api_url` = base URL of this service, e.g. `http://scan-api:8686`
- `local_scan_api_shared_dir` = the shared volume path, e.g. `/shared/zanshin-scans`
  (must be the exact same path this service sees on its side)

## Running it directly (without Docker)

If you'd rather run this service as a plain process on the host (simplest
way to guarantee "same filesystem" without any volume setup at all):

```bash
pip install -r requirements.txt
# plus: install syft, grype, gitleaks on PATH (see their own install docs)
uvicorn main:app --host 0.0.0.0 --port 8686
```

## Security

This service has **no authentication** and will run arbitrary scans (and,
for `/sbom/image`, pull arbitrary registry images) for anyone who can reach
it. Do not expose it to the internet or an untrusted network — bind it to
localhost or an internal/private network shared only with Zanshin.

## Known limitation / not verified end-to-end

This service and its Dockerfile were written without access to Docker or
external network in the environment that authored them, so the tool
install steps (Syft/Grype install scripts, the gitleaks release URL/version
pin) and the exact JSON shapes each CLI produces have not been exercised
against real installs — only against simulated responses in Zanshin's own
test suite for `LocalApiScannerEngine`. Verify a full round trip (a real
scan through this service) before relying on it, and update the gitleaks
version pin in the Dockerfile — it will go stale.
