#!/usr/bin/env sh
#
# The digest the GitLab template pins is the digest of the gate script beside it.
#
# The template runs the release's `vectispire-gate.sh` only when its SHA-256 matches the one the
# template carries. Edit the script without the template and every pipeline including the next
# release refuses to run — on someone else's runner, after the tag, where nothing here can see it.
# So this runs on every push (`ci.yml`) and again before a release is built (`release.yml`).

set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
template="$root/ci/gitlab/vectispire-gate.gitlab-ci.yml"
script="$root/ci/vectispire-gate.sh"

pinned=$(sed -n 's/^ *VECTISPIRE_GATE_SHA256: *"\([0-9a-f]\{64\}\)".*/\1/p' "$template")
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$script" | cut -d' ' -f1)
else
    actual=$(shasum -a 256 "$script" | cut -d' ' -f1)
fi

if [ -z "$pinned" ]; then
    echo "check-gate-pin: no VECTISPIRE_GATE_SHA256 found in $template" >&2
    exit 1
fi
if [ "$pinned" != "$actual" ]; then
    echo "check-gate-pin: the GitLab template pins a gate script that is not ci/vectispire-gate.sh." >&2
    echo "  pinned: $pinned" >&2
    echo "  actual: $actual" >&2
    echo "Set VECTISPIRE_GATE_SHA256 in ci/gitlab/vectispire-gate.gitlab-ci.yml to the actual digest." >&2
    exit 1
fi
echo "check-gate-pin: the GitLab template pins ci/vectispire-gate.sh ($actual)."
