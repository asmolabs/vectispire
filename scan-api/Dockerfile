# Zanshin Scan API — sidecar service for ScannerEngine's "local_api" backend
# (docs/architecture/01). See README.md before deploying: this image has not
# been built/run in the environment that authored it (no Docker/network
# access there) — verify the install steps and tool versions below work on
# your infrastructure before relying on it.

FROM python:3.12-slim

# curl: tool installers below. git: some checkov checks/frameworks expect it.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

# Syft + Grype — official Anchore install scripts (installs latest release
# to /usr/local/bin). Pin a version here instead if you need reproducible
# builds: see each project's install.sh for the `-b <dir> <version>` form.
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# gitleaks — GitHub release tarball. Check
# https://github.com/gitleaks/gitleaks/releases for the current version
# before building; this pin will go stale.
ARG GITLEAKS_VERSION=8.21.2
RUN curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

WORKDIR /app
COPY requirements.txt .
# fastapi/uvicorn + checkov (a Python package, so it lives here rather than
# in the curl-installed binaries above)
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8686
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8686"]
