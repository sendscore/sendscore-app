# syntax=docker/dockerfile:1

# The engine (github.com/sendscore/sendscore) is the version go.mod names.
# ENGINE_VERSION overrides it with another tag, a commit, or a pseudo-version.
#
#   docker build --build-arg ENGINE_VERSION=v0.2.0 -t sendscore-app .

FROM golang:1.26.10-trixie@sha256:a050dcceee6eb9bf110151662dfac7662f3bec40927c7dee48731e3d92083d42 AS build
ARG ENGINE_VERSION=
WORKDIR /src/sendscore-app
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eu; \
    if [ -n "$ENGINE_VERSION" ]; then \
      go get github.com/sendscore/sendscore@"$ENGINE_VERSION"; \
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
# The image has no shell or curl, so the binary checks itself.
HEALTHCHECK --interval=30s --timeout=6s --start-period=15s CMD ["/usr/local/bin/sendscore-app", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/sendscore-app"]
