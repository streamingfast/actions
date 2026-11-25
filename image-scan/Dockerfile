# syntax=docker/dockerfile:1
#
# ghcr.io/streamingfast/image-scan: the image-scan Go program and the Docker Scout CLI it runs. Every base is pinned by digest
# (the index, so the same Dockerfile builds linux/amd64 and linux/arm64, the Go program is cross-compiled), bump by hand.

FROM --platform=$BUILDPLATFORM golang:1.26-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/image-scan ./cmd/image-scan

# The Docker Scout CLI, as published by Docker (Docker Subscription Service Agreement, see the README of image-scan)
FROM docker/scout-cli:1.30.0@sha256:01f7e63d8ee0668b2c19f09920d7e7eff8d3e507ca931df2b8c00ae19b71d588 AS scout

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
# git for scan-paths (git diff HEAD^1 HEAD of the bind-mounted checkout), CA certificates for the registries and the GitHub API
RUN apk add --no-cache ca-certificates git
COPY --from=scout /docker-scout /usr/local/bin/docker-scout
COPY --from=build /out/image-scan /usr/local/bin/image-scan
# The action runs the container as the runner user (to write GITHUB_OUTPUT), which has no home directory in the image
ENV HOME=/tmp
ENTRYPOINT ["/usr/local/bin/image-scan"]
