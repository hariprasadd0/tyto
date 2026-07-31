# syntax=docker/dockerfile:1

FROM golang:1.25-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libbpf-dev \
    linux-libc-dev \
    llvm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY src/userspace/go.mod src/userspace/go.sum ./src/userspace/
RUN cd src/userspace && go mod download

COPY src/ ./src/
RUN cd src/userspace && go generate && go build -o tyto .

FROM ubuntu:24.04

COPY --from=builder /build/src/userspace/tyto /tyto

# XDP attaches to host interfaces: run with --privileged --network host
ENTRYPOINT ["/tyto"]
