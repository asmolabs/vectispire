# Vectispire as one image: the Spring Boot control plane with the Angular interface inside it.
#
#   docker build -t vectispire .
#   docker run --rm -p 3180:3180 \
#     -e VECTISPIRE_DB_URL=jdbc:postgresql://db:5432/vectispire \
#     -e VECTISPIRE_DB_USER=vectispire -e VECTISPIRE_DB_PASSWORD=... \
#     -e ENCRYPTION_KEY=... \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     vectispire
#
# **One origin, and that is the reason for the shape.** The interface is served by the same
# process that serves the API, so there is no proxy to configure, no CORS, and no pair of
# artifacts that have to agree on a port. It also makes `connect-src 'self'` a true statement
# rather than an aspiration.
#
# See `docs/architecture/04-runtime-and-deployment.md` for the filtering-proxy configuration
# (`DOCKER_HOST`, one variable, no code change) and — more importantly — for why that proxy
# shrinks the blast radius without closing the escape.
#
# **The Docker socket is mounted, and that is the trade-off to know.** The built-in worker runs
# the scanners as sibling containers; reaching that socket is equivalent to root on the host.
# A deployment that cannot accept it should set `VECTISPIRE_EMBEDDED_WORKER=false` and give the
# work to a remote agent instead — which is the whole reason agents exist (decision 0003).

# --- The interface -----------------------------------------------------------------------
# Its own stage so the JDK image never needs Node. The alternative — one image with both —
# installs a toolchain into the build layer of something that has no other use for it.
FROM node:24-alpine AS ui

WORKDIR /src
# Manifests first: the install layer is rebuilt only when dependencies change, not on every
# edit to a component.
COPY package.json package-lock.json ./
COPY vectispire-angular/package.json vectispire-angular/
RUN npm ci --ignore-scripts

COPY vectispire-angular/ vectispire-angular/
RUN npm run build --workspace @vectispire/frontend

# --- The jar -----------------------------------------------------------------------------
FROM eclipse-temurin:25-jdk-alpine AS build

WORKDIR /src
# The wrapper and the build definition before the sources, for the same layering reason: the
# dependency resolution is what takes time, and it does not depend on the code.
COPY vectispire-java/gradle/ gradle/
COPY vectispire-java/gradlew vectispire-java/settings.gradle.kts vectispire-java/build.gradle.kts ./
COPY vectispire-java/buildSrc/ buildSrc/
# The empty module directories exist only so that this warm-up can run: `settings.gradle.kts`
# declares three projects and Gradle refuses to configure one whose directory is missing.
RUN mkdir -p vectispire-common vectispire-core vectispire-agent && ./gradlew --no-daemon help

COPY vectispire-java/ ./
COPY --from=ui /src/vectispire-angular/dist/vectispire/browser /ui

# `-PuiDist` rather than `-Pui`: the interface is already built, and asking Gradle to build it
# again here is what would drag Node into this stage.
RUN ./gradlew --no-daemon :vectispire-core:bootJar -PuiDist=/ui -x test

# --- The image that runs -----------------------------------------------------------------
FROM eclipse-temurin:25-jre-alpine

# `git` is what clones the repositories the built-in worker scans. The Docker *client* is not
# needed: the worker talks to the daemon over the mounted socket, from Java.
RUN apk add --no-cache git openssh-client ca-certificates

WORKDIR /app
COPY --from=build /src/vectispire-core/build/libs/vectispire-core.jar app.jar

# The image is a redistribution, so the licence and the notice travel with it: Apache-2.0
# clause 4 asks for both in every copy, and an image that carries the code without them is
# the non-compliance Vectispire exists to report on other people's containers.
COPY LICENSE NOTICE ./

# An unprivileged user. It still has to belong to the group that owns the Docker socket on the
# host, which the deployment grants with `--group-add`.
RUN addgroup -S vectispire && adduser -S -G vectispire vectispire

# **Where the audit mirror lands, created here so the volume inherits its owner.**
# The mirror is off by default in `application.yaml` — writing to a path by default fails on a
# read-only filesystem, and an integrity control that warns on every start is one people learn to
# ignore. A container deployment is the case where a writable volume does exist, so `compose`
# switches it on by pointing `VECTISPIRE_AUDIT_MIRROR` here.
#
# The directory must exist *and* be owned by the unprivileged user before the volume is mounted:
# Docker initialises an empty named volume from what it finds at the mount point, ownership
# included. Without this the volume arrives root-owned, every append fails with a permission
# error, and the mirror is present in configuration and absent in fact — the one outcome worse
# than having no mirror.
RUN mkdir -p /var/lib/vectispire/audit && chown vectispire:vectispire /var/lib/vectispire/audit

USER vectispire

EXPOSE 3180

# No HEALTHCHECK on the API port alone: the process answers before it can serve anything
# useful if the database is unreachable. Actuator's health endpoint is the one that knows,
# and it is deliberately the only actuator path open without a token.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
    CMD wget -qO- http://localhost:3180/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
