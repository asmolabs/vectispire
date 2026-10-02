#!/usr/bin/env sh
#
# The digest the interface's CI/CD snippets pin is the digest of the CLI beside them.
#
# The snippets on Repositories → CI/CD download the release's `vectispire-cli.sh` and run it only
# when its SHA-256 is the `CLI_SCRIPT_SHA256` written in the interface. The interface and the asset
# come from the same tag, so the pin is right exactly when it is the digest of
# `scripts/vectispire-cli.sh` in this tree. Edit the CLI without the pin and every snippet copied
# from the next release refuses to run — in someone else's pipeline, after the tag, where nothing
# here can see it. So this runs on every push (`ci.yml`) and again before a release is built
# (`release.yml`), as `ci/gitlab/check-gate-pin.sh` does for the gate script.

set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
source="$root/vectispire-angular/src/app/pages/repositories/repositories.ts"
script="$root/scripts/vectispire-cli.sh"

pinned=$(sed -n "s/^const CLI_SCRIPT_SHA256 = '\([0-9a-f]\{64\}\)';.*/\1/p" "$source")
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$script" | cut -d' ' -f1)
else
    actual=$(shasum -a 256 "$script" | cut -d' ' -f1)
fi

if [ -z "$pinned" ]; then
    echo "check-cli-pin: no CLI_SCRIPT_SHA256 found in $source" >&2
    exit 1
fi
if [ "$pinned" != "$actual" ]; then
    echo "check-cli-pin: the interface's CI/CD snippets pin a CLI that is not scripts/vectispire-cli.sh." >&2
    echo "  pinned: $pinned" >&2
    echo "  actual: $actual" >&2
    echo "Set CLI_SCRIPT_SHA256 in vectispire-angular/src/app/pages/repositories/repositories.ts to the actual digest." >&2
    exit 1
fi
echo "check-cli-pin: the interface's CI/CD snippets pin scripts/vectispire-cli.sh ($actual)."
