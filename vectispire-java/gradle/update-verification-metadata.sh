#!/usr/bin/env bash
#
# Records what the build resolves in `gradle/verification-metadata.xml` and the public keys that
# signed it in `gradle/verification-keyring.keys`. Run it after changing a dependency or a plugin
# (a Dependabot pull request included), then **read the diff** before committing it: this script
# is where trust is extended, and a regeneration nobody reviewed turns verification into a
# rubber stamp.
#
#   cd vectispire-java && ./gradle/update-verification-metadata.sh
#
# Why it is a script rather than one Gradle command — each line below is a trap that was hit:
#
# - **A fresh Gradle home, every time.** Gradle records what it downloads during the run, and a
#   warm cache serves parsed POMs without reading their parents: a second generation on a warm
#   home dropped `jakarta.platform`'s BOM parent, and the next build on a clean runner failed
#   verification. A clean home is what CI has.
# - **Every task CI runs**, so every configuration they resolve is recorded: `build`, the engine
#   campaign, the agent's integration suite, both jars and both image builds. A task CI adds later
#   resolves nothing new until it is added here too — and fails CI until then, which is the point.
# - **Key servers are switched on for the run only.** The committed file disables them, so a
#   build never fetches a key and never depends on a key server being up; a new signer's key is
#   fetched here, once, and committed in the keyring. Gradle's first generation lost 22 of 115
#   keys to key-server failures and silently fell back to checksums for their artifacts, so a key
#   that cannot be downloaded fails this script instead of weakening the file.
# - **`--dry-run`**: resolution alone records the artifacts, nothing is compiled or executed, and
#   Gradle writes `*.dryrun.*` files beside the real ones, moved into place at the end.
#
# Gradle merges into the existing file: entries for versions no longer used stay until someone
# regenerates from an empty `<components/>`, which is harmless and can be done at leisure.
set -euo pipefail

cd "$(dirname "$0")/.."
metadata=gradle/verification-metadata.xml
keyring=gradle/verification-keyring.keys
disabled='<key-servers enabled="false"/>'

grep -qF "$disabled" "$metadata" || {
  echo "$metadata does not disable key servers; refusing to regenerate over an unexpected file." >&2
  exit 1
}

home="$(mktemp -d)"
restore_disabled() {
  # Put the switch back whatever happened, so an interrupted run never leaves key servers on.
  if ! grep -qF "$disabled" "$metadata"; then
    perl -0pi -e 's|(<keyring-format>armored</keyring-format>)|$1\n      <key-servers enabled="false"/>|' "$metadata"
  fi
  rm -rf "$home" gradle/verification-metadata.dryrun.xml gradle/verification-keyring.dryrun.keys
}
trap restore_disabled EXIT

# The wrapper's distribution is not a dependency: reuse the one already unpacked and checked
# against `distributionSha256Sum`, rather than downloading 130 MB into each fresh home.
existing="${GRADLE_USER_HOME:-$HOME/.gradle}/wrapper"
[ -d "$existing" ] && ln -s "$existing" "$home/wrapper"

perl -0pi -e 's|\n\s*<key-servers enabled="false"/>||' "$metadata"

# stdout is the dry run's list of skipped tasks; failures go to stderr and stay visible.
GRADLE_USER_HOME="$home" ./gradlew --no-daemon --quiet \
  --write-verification-metadata pgp,sha256 --export-keys --dry-run \
  build integrationTestAll :vectispire-common:integrationTest \
  :vectispire-core:bootJar :vectispire-agent:bootJar \
  :vectispire-core:jibBuildTar :vectispire-agent:jibBuildTar \
  :vectispire-core:jibDockerBuild :vectispire-agent:jibDockerBuild >/dev/null

mv gradle/verification-metadata.dryrun.xml "$metadata"
mv gradle/verification-keyring.dryrun.keys "$keyring"

if grep -q '<ignored-key ' "$metadata"; then
  echo >&2
  echo "Some keys could not be downloaded, and their artifacts fell back to checksums:" >&2
  grep -o '<ignored-key id="[0-9A-F]*"' "$metadata" | cut -d'"' -f2 >&2
  echo >&2
  echo "Restore both files (git checkout -- $metadata $keyring), append each key to $keyring" >&2
  echo "  curl -sf 'https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x<id>' >> $keyring" >&2
  echo "check its fingerprint and owner against the publisher's, and run this script again." >&2
  exit 1
fi

echo "Regenerated. Review before committing:"
echo "  - a new <trusted-key>: whose key is it (its uid is in $keyring, or on keyserver.ubuntu.com), and does it belong to the group it is trusted for?"
echo "  - a new <sha256>: an unsigned artifact (the Plugin Portal's are), pinned to the bytes downloaded just now."
git diff --stat -- "$metadata" "$keyring"
