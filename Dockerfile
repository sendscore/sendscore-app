# syntax=docker/dockerfile:1

# The engine (github.com/sendscore/sendscore) comes from one of two places.
#
# A local checkout, passed as a named build context. go.mod's replace
# directive points at ../sendscore, and the engine is copied there.
#
#   docker build --build-context engine=../sendscore -t sendscore-app .
#
# Or a published version, fetched from GitHub with the replace dropped.
#
#   docker build --build-arg ENGINE_VERSION=v0.1.0 -t sendscore-app .
#
# This stage stands in for the engine when no build context replaces it. It
# copies a file so it is not empty, because BuildKit reuses an empty stage's
# cache from an earlier build that had the engine.
FROM scratch AS engine
COPY .dockerignore /.placeholder

FROM golang:1.26.10-trixie@sha256:a050dcceee6eb9bf110151662dfac7662f3bec40927c7dee48731e3d92083d42 AS build
ARG ENGINE_VERSION=
WORKDIR /src/sendscore-app
COPY --from=engine / /src/sendscore/
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    if [ -n "$ENGINE_VERSION" ]; then \
      go mod edit -dropreplace=github.com/sendscore/sendscore -droprequire=github.com/sendscore/sendscore; \
      go get github.com/sendscore/sendscore@"$ENGINE_VERSION"; \
    elif [ ! -f /src/sendscore/go.mod ]; then \
      echo "No engine. Pass --build-context engine=../sendscore or --build-arg ENGINE_VERSION=<version>" >&2; \
      exit 1; \
    fi; \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sendscore-app .; \
    mkdir -p /out/data

# Distroless static has CA certificates and tzdata (the binary also embeds
# time/tzdata), no shell, and runs as nonroot (65532).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
COPY --from=build /out/sendscore-app /usr/local/bin/sendscore-app
# A new named volume takes this directory's owner, so nonroot can write it.
COPY --from=build --chown=65532:65532 /out/data /data
ENV SENDSCORE_ADDR=0.0.0.0:3014 \
    SENDSCORE_SMTP_ADDR=0.0.0.0:2525 \
    SENDSCORE_DB=/data/sendscore.db \
    SENDSCORE_BASE_URL=http://127.0.0.1:3014
VOLUME /data
EXPOSE 3014 2525
USER nonroot:nonroot
# The app gives open sessions up to a minute on SIGTERM, so stop with a
# timeout over 60 seconds (docker stop -t 90, or stop_grace_period: 90s).
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/sendscore-app"]
