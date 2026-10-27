#!/bin/sh
# The agent's image, built twice from nothing, must be the same image.
#
# A signature (release.yml) says who built an image; only a reproducible build lets anyone else check
# that the image is what the source says. Both builds start without cache, with the commit's time as
# SOURCE_DATE_EPOCH and BuildKit rewriting the layers' timestamps to it, so that the only inputs left
# are the source, the lockfile and the pinned base and toolchain. The image ids (the configuration's
# digest, which names every layer's) are compared, and so are the binaries, which says where a
# difference comes from when there is one.
#
# Usage: security/reproducible-image.sh [platform] — linux/amd64 by default, as CI's runner builds.
set -eu
cd "$(dirname "$0")/.."
platform=${1:-linux/amd64}
epoch=$(git log -1 --format=%ct 2>/dev/null || echo 0)
work=$(mktemp -d "${TMPDIR:-/tmp}/vs-rs-repro.XXXXXX")
# A builder of its own, BuildKit pinned by digest: the default `docker` driver writes an OCI archive only where the
# daemon keeps its images in containerd — Docker Desktop does, GitHub's runner does not ("OCI exporter is not
# supported for the docker driver"), and the job failed before building anything. Pinned, BuildKit is also one input
# fewer that differs from one machine to the next.
builder="vs-rs-repro-$$"
docker buildx create --name "$builder" --driver docker-container \
  --driver-opt image=moby/buildkit:v0.26.2@sha256:de10faf919fc71ba4eb1dd7bd6449566d012b0c9436b1c61bfee21d621b009aa \
  >/dev/null
trap 'docker buildx rm "$builder" >/dev/null 2>&1; rm -rf "$work"' EXIT

# An OCI archive rather than the daemon's store: BuildKit rewrites timestamps only on an export it
# writes itself, and the archive's manifest digest is the image's identity, whatever loads it later.
build() {
  docker buildx build --builder "$builder" --quiet --no-cache --platform "$platform" -f Dockerfile.agent \
    --build-arg SOURCE_DATE_EPOCH="$epoch" \
    --output "type=oci,dest=$work/$1.tar,rewrite-timestamp=true" . >/dev/null
}
# The manifest's digest, and the sha256 of /vectispire-agent inside its one layer.
identity() {
  python3 - "$work/$1.tar" <<'PY'
import gzip, hashlib, io, json, sys, tarfile
oci = tarfile.open(sys.argv[1])
blob = lambda d: oci.extractfile("blobs/sha256/" + d.split(":", 1)[1]).read()
index = json.load(oci.extractfile("index.json"))
manifest_digest = index["manifests"][0]["digest"]
manifest = json.loads(blob(manifest_digest))
if manifest.get("mediaType", "").endswith("index.v1+json") or "manifests" in manifest:
    manifest_digest = manifest["manifests"][0]["digest"]
    manifest = json.loads(blob(manifest_digest))
binary = None
for layer in manifest["layers"]:
    data = blob(layer["digest"])
    if layer["mediaType"].endswith("gzip"):
        data = gzip.decompress(data)
    for member in tarfile.open(fileobj=io.BytesIO(data)):
        if member.name.lstrip("./") == "vectispire-agent":
            binary = hashlib.sha256(tarfile.open(fileobj=io.BytesIO(data)).extractfile(member.name).read()).hexdigest()
print(manifest_digest, binary or "no-binary")
PY
}

build a
build b
# shellcheck disable=SC2046 # two words each, split on purpose: digest, then binary hash
set -- $(identity a) $(identity b)
echo "platform $platform, SOURCE_DATE_EPOCH=$epoch"
echo "image:  $1"
echo "        $3"
echo "binary: $2"
echo "        $4"
if [ "$2" = no-binary ]; then echo "no /vectispire-agent in the image: nothing was compared"; exit 1; fi
if [ "$2" != "$4" ]; then
  echo "two builds of one commit gave two binaries: the compiler's inputs are not all pinned"; exit 1
fi
if [ "$1" != "$3" ]; then
  echo "the binaries agree but the images differ: a layer carries a timestamp or a build-time value"; exit 1
fi
echo "reproducible"
