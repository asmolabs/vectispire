# A throwaway forge for the clone tests: git over SSH (sshd and git-shell) and over HTTPS (git's own
# http-backend behind a small TLS server), with a certificate authority made at start. Never shipped.
# checkov:skip=CKV_DOCKER_1: it is an SSH forge; port 22 is what the tests clone over, on loopback only.
# checkov:skip=CKV_DOCKER_3: sshd and the TLS server need root to bind 22 and 443 and to switch to the
# git user per session; the container lives for one test, on a loopback port.
# checkov:skip=CKV_DOCKER_2: each test waits for the forge's own readiness file, not a health state.
FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
RUN apk add --no-cache git git-daemon openssh-server openssl python3
COPY entrypoint.sh https_forge.py /forge/
RUN chmod 0755 /forge/entrypoint.sh
EXPOSE 22 443
ENTRYPOINT ["/forge/entrypoint.sh"]
