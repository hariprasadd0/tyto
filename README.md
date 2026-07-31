# Tyto

A simple XDP program to rate-limit UDP, TCP SYN, and ICMP floods at the network interface.

## Build

Requirements: Go 1.25+, clang, libbpf-dev, linux headers.

```bash
make build          # regenerates BPF objects and compiles the Go binary
sudo ./src/userspace/tyto eth0            # rate-limit on eth0
sudo ./src/userspace/tyto eth0 --allow    # also allowlist the interface's own IP
```

Rate limits (per source IP, 1s window): UDP 800/s, TCP SYN 100/s, ICMP 500/s — tunable in `src/xdp/tyto_xdp.c`.

## Container

The XDP program attaches to a host interface, so the container must run privileged
with the host network namespace:

```bash
make docker-build
docker run --rm --privileged --network host tyto eth0
```

Prebuilt image: `ghcr.io/hariprasadd0/tyto:latest` (see `tests/docker-compose.yaml`).

## gRPC API

Server on `:50051`:

- `StreamEvents` — streams blocked-IP events in real time
- `GetStats` — aggregated packet/drop counters per protocol

## CI

GitHub Actions (`.github/workflows/ci.yml`) on push/PR:

1. `build` — regenerate BPF objects, verify committed bindings haven't drifted, vet, compile
2. `docker` — build and push the image to GHCR (`latest` on main, version tags on `v*`)
3. `smoke` — attach XDP to a dummy interface in a privileged container and verify alerts/stats
