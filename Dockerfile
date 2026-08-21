# Zanshin as one image: the Spring Boot control plane with the Angular interface inside it.
#
#   docker build -t zanshin .
#   docker run --rm -p 8000:8000 \
#     -e ZANSHIN_DB_URL=jdbc:postgresql://db:5432/zanshin \
#     -e ZANSHIN_DB_USER=zanshin -e ZANSHIN_DB_PASSWORD=... \
#     -e ENCRYPTION_KEY=... \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     zanshin
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
# A deployment that cannot accept it should set `ZANSHIN_EMBEDDED_WORKER=false` and give the
# work to a remote agent instead — which is the whole reason agents exist (decision 0003).

# --- The interface -----------------------------------------------------------------------
# Its own stage so the JDK image never needs Node. The alternative — one image with both —
# installs a toolchain into the build layer of something that has no other use for it.
FROM node:24-alpine AS ui

WORKDIR /src
# Manifests first: the install layer is rebuilt only when dependencies change, not on every
# edit to a component.
COPY package.json package-lock.json ./
COPY zanshin-angular/package.json zanshin-angular/
RUN npm ci --ignore-scripts

COPY zanshin-angular/ zanshin-angular/
RUN npm run build --workspace @zanshin/frontend

# --- The jar -----------------------------------------------------------------------------
FROM eclipse-temurin:25-jdk-alpine AS build

WORKDIR /src
# The wrapper and the build definition before the sources, for the same layering reason: the
# dependency resolution is what takes time, and it does not depend on the code.
COPY zanshin-java/gradle/ gradle/
COPY zanshin-java/gradlew zanshin-java/settings.gradle.kts zanshin-java/build.gradle.kts ./
COPY zanshin-java/buildSrc/ buildSrc/
# The empty module directories exist only so that this warm-up can run: `settings.gradle.kts`
# declares three projects and Gradle refuses to configure one whose directory is missing. The
# COPY below replaces them. Without this step the dependency download repeats on every change
# to a source file, which is most of the build time.
RUN mkdir -p zanshin-common zanshin-core zanshin-agent && ./gradlew --no-daemon help

COPY zanshin-java/ ./
COPY --from=ui /src/zanshin-angular/dist/zanshin/browser /ui

# `-PuiDist` rather than `-Pui`: the interface is already built, and asking Gradle to build it
# again here is what would drag Node into this stage.
RUN ./gradlew --no-daemon :zanshin-core:bootJar -PuiDist=/ui -x test

# --- The image that runs -----------------------------------------------------------------
FROM eclipse-temurin:25-jre-alpine

# `git` is what clones the repositories the built-in worker scans. The Docker *client* is not
# needed: the worker talks to the daemon over the mounted socket, from Java.
RUN apk add --no-cache git openssh-client ca-certificates

WORKDIR /app
COPY --from=build /src/zanshin-core/build/libs/zanshin-core.jar app.jar

# An unprivileged user. It still has to belong to the group that owns the Docker socket on the
# host, which the deployment grants with `--group-add`.
RUN addgroup -S zanshin && adduser -S -G zanshin zanshin
USER zanshin

EXPOSE 8000

# No HEALTHCHECK on the API port alone: the process answers before it can serve anything
# useful if the database is unreachable. Actuator's health endpoint is the one that knows,
# and it is deliberately the only actuator path open without a token.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
    CMD wget -qO- http://localhost:8000/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "app.jar"]
