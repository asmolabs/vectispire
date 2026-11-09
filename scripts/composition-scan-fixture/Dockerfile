# The servers `scripts/composition-scan-check.sh` clones its fixture repository from: `git daemon`
# for the plain clone, `sshd` for the keyed one. Built by the script, never published.
#
# **Built from a base pinned by digest, with its packages installed at build time.** The fixture
# used to be `alpine:3.22` by tag running `apk add` at every start: a tag that moves under the check,
# and a check that needed the package mirror each time a container started — the SSH fixture's
# restart with its second host key included. The multi-architecture index digest, so the runner's
# amd64 and a developer's arm64 build the same release.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8

# The account the SSH clone logs in as: `git-shell` rather than a shell, and a password field of `*`
# instead of `!`, which OpenSSH reads as a locked account and refuses even a key for.
RUN apk add --no-cache git git-daemon openssh-server \
    && adduser -D -s /usr/bin/git-shell git \
    && sed -i 's/^git:!/git:*/' /etc/shadow

# `git daemon` needs nothing more than reading the served tree. The SSH fixture runs as root, set in
# the check's override: sshd separates privileges and installs the keys it is handed at start.
USER git

# checkov:skip=CKV_DOCKER_2: nothing waits on this fixture's health — the check reads sshd's own
# "Server listening" line after a restart, and a clone fails loudly if the daemon is not up.
CMD ["git", "-c", "safe.directory=*", "daemon", "--reuseaddr", "--export-all", "--base-path=/srv", "/srv"]
