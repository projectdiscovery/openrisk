# Pinning apk package versions breaks the build once Alpine drops them; the base image tag is the pin.
# hadolint global ignore=DL3018
FROM golang:1.26.10-alpine AS build-env
RUN apk add --no-cache build-base git
WORKDIR /app
COPY . /app
RUN go mod download && go build ./cmd/openrisk

FROM alpine:3.24.2
RUN apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /app/openrisk /usr/local/bin/openrisk
ENTRYPOINT ["openrisk"]
