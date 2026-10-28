#!/usr/bin/env bash
#
# **Pulls digest-pinned images, retrying a registry that did not answer.** For the scanner images
# `ScannerImages` pins, which CI runs with `docker run` — and `docker run` pulls once: on pull request
# #56 the `images` job went red because Docker Hub timed out in the TLS handshake while the composition
# check pulled the matcher (`net/http: TLS handshake timeout`, exit 125), and a re-run with nothing
# changed was green. A red run that a re-run turns green teaches everyone to re-run red runs.
#
#   scripts/pull-pinned-image.sh anchore/grype@sha256:<64 hex> [more…]
#
# Called ahead of the `docker run`, which then finds the image present and pulls nothing.
#
# **A pull that still fails after the last attempt fails the caller**, exit 1, with the image named:
# the scanner cannot run without it, and a step that skipped its scan would report a green that read
# nothing. Every failure is retried, not only the ones that look transient — telling "the registry did
# not answer" from "the digest does not exist" means parsing the daemon's wording, which changes; a
# digest that does not exist costs the backoff (70s by default) before the same red.
#
# **Only a digest is accepted.** Retrying a tag could return a different image on each attempt, and the
# pins are the point: the version that scans the targets is the version that scans Vectispire.
#
# PULL_ATTEMPTS (default 4) attempts, PULL_BACKOFF (default 10) seconds before the second, doubled
# before each next one: 10, 20, 40. An image already present is not pulled again — the digest is its
# content, so present means the same bytes.
set -euo pipefail

attempts="${PULL_ATTEMPTS:-4}"
backoff="${PULL_BACKOFF:-10}"

[ "$#" -gt 0 ] || { echo "usage: $0 image@sha256:<digest>…" >&2; exit 2; }
for image in "$@"; do
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || { echo "✗ $image is not pinned by digest (…@sha256:<64 hex>)" >&2; exit 2; }
done

for image in "$@"; do
  docker image inspect "$image" > /dev/null 2>&1 && continue
  wait="$backoff"
  for (( attempt = 1; ; attempt++ )); do
    # The daemon's error stays on stderr: it is what the log of a final failure has to show.
    docker pull --quiet "$image" > /dev/null && break
    if (( attempt >= attempts )); then
      echo "✗ $image: not pulled after $attempts attempts" >&2
      exit 1
    fi
    # A retry that succeeds leaves no red, so it is annotated: a registry that needs one on every run
    # is a fact to see on the run's summary, not to find in a log.
    message="pull of $image failed (attempt $attempt of $attempts), again in ${wait}s"
    if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::warning::$message"; else echo "$message" >&2; fi
    sleep "$wait"
    wait=$(( wait * 2 ))
  done
done
