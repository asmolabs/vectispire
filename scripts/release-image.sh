#!/usr/bin/env bash
#
# The previous release's image, by digest, verified as signed by its release workflow, and pulled.
# Prints `<tag> <image@sha256:…>` on stdout and nothing else; what it did goes to stderr.
#
# Two checks start an image of the last release against this commit: the upgrade drill (the control
# plane, `scripts/upgrade-drill.sh`) and the previous agent's check (the agent, decision 0043 §2, the
# `previous-agent` job of `ci.yml`). Both ran the same twenty lines before this file; one copy is what
# keeps a fix of one from being missed by the other.
#
# **The release is the newest `v*` tag this commit descends from**, release candidates included, and
# `v0.11.0` after `v0.11.0-rc.3`: the newest thing an installation can be running. A tag on another
# line is not where this commit's users come from. The checkout needs its tags (`fetch-depth: 0`).
#
# **By digest, asked of the registry before anything is pulled**, so that everything after — the
# verification, the pull, the run, the log — names those bytes whatever the tag does meanwhile.
# `json .Manifest` rather than `.Manifest.Digest`: Docker Desktop's buildx ignores that template on a
# single-platform manifest and prints the whole description instead.
#
# **Verified before it is pulled, with the command a consumer runs.** The image is about to be handed
# a database's password, an encryption key or an agent's key; "the digest the registry serves" says
# which bytes, not whose. The identity names the release workflow at that tag and the issuer GitHub's
# OIDC — the pair `release.yml` signs with and then verifies itself. Anything but cosign's exit 0 stops
# here, and there is no switch to skip it: a check that ran an unverified image and passed would be
# green over the one thing it never looked at. Verifying needs no credential — the image and its
# signature are public, the trust root is Sigstore's — only the network.
#
# Usage:
#   scripts/release-image.sh vectispire-agent                   # the newest release's agent
#   TAG=v0.11.1 scripts/release-image.sh vectispire             # a given release
#   TAG=v0.11.1 IMAGE=ghcr.io/asmolabs/vectispire@sha256:… scripts/release-image.sh vectispire
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

NAME="${1:?the name of the image: vectispire, vectispire-agent or vectispire-report-demo}"
REGISTRY="${REGISTRY:-ghcr.io/asmolabs}"
# `ImageSignatureVerifier.COSIGN`: v3.1.3, the release workflow's version, by the digest of its
# multi-architecture index — one pin for the verifier the product runs and the one the checks run,
# native on the runner and on arm64. Not overridable: a verifier the environment chooses verifies
# whatever the environment wants.
COSIGN_IMAGE="ghcr.io/sigstore/cosign/cosign@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8"

fail() { printf 'release-image: %s\n' "$*" >&2; exit 1; }

TAG="${TAG:-}"
IMAGE="${IMAGE:-}"
if [ -z "$IMAGE" ]; then
  [ -n "$TAG" ] || TAG="$(git -c versionsort.suffix=-rc tag -l 'v*' --merged HEAD --sort=-v:refname | head -n 1)"
  [ -n "$TAG" ] || fail "no v* tag reachable from HEAD — the checkout needs its tags (fetch-depth: 0)"
  digest="$(docker buildx imagetools inspect "$REGISTRY/$NAME:${TAG#v}" --format '{{json .Manifest}}' \
    | python3 -c 'import json, sys; print(json.load(sys.stdin).get("digest", ""))')" \
    || fail "$REGISTRY/$NAME:${TAG#v} cannot be resolved — was $TAG published?"
  case "$digest" in
    sha256:*) ;;
    *) fail "$REGISTRY/$NAME:${TAG#v} resolved to [$digest], not a digest" ;;
  esac
  IMAGE="$REGISTRY/$NAME@$digest"
else
  # A given image is held to the resolved one's rule: by digest, and verified against the tag it
  # stands for. An image its release workflow did not sign is not the previous release.
  case "$IMAGE" in
    *@sha256:*) ;;
    *) fail "IMAGE must name a digest (…@sha256:…), not [$IMAGE]" ;;
  esac
  [ -n "$TAG" ] || fail "IMAGE needs TAG: its signature is checked against that tag's release workflow"
fi

identity="https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/$TAG"
issuer="https://token.actions.githubusercontent.com"
err="$(mktemp)"
trap 'rm -f "$err"' EXIT
docker run --rm --cap-drop ALL --security-opt no-new-privileges "$COSIGN_IMAGE" verify \
    "--certificate-identity=$identity" "--certificate-oidc-issuer=$issuer" "$IMAGE" > /dev/null 2> "$err" \
  || { sed 's/^/    /' "$err" >&2; fail "$IMAGE is not verified as signed by $identity — not run"; }
sed -e '/^[[:space:]]*$/d' -e 's/^/  cosign: /' "$err" >&2
docker pull -q "$IMAGE" > /dev/null || fail "$IMAGE cannot be pulled"
printf '%s %s\n' "$TAG" "$IMAGE"
