# Bounded Nmap runtime

This target-facing image is separate from the network-free native Nmap version proof.

- Base: official Kali `kali-rolling` amd64 manifest pinned by SHA-256.
- Package: Kali `nmap=7.99+dfsg-1kali1`.
- Runtime user: `65534:65534`.
- No scripts, wordlists, shells or extra tools are installed deliberately.

Upstream references:

- [Official Kali Docker image guidance](https://www.kali.org/docs/containers/official-kalilinux-docker-images/)
- [Kali Nmap 7.99 package migration](https://pkg.kali.org/news/684801/nmap-799dfsg-1kali1-migrated-to-kali-rolling/)

Building the image does not enable execution. The adapter remains disabled until the Redmi is isolated and an exact isolation attestation is supplied.

The runtime broker must still enforce `--pull=never`, a read-only filesystem, all capabilities dropped, no-new-privileges, CPU/memory/PID limits, a dedicated isolated network, an exact target and bounded TCP ports.

## Reproducible local build

Run inside Kali WSL:

```bash
./containers/nmap/build-in-kali.sh
```

Kali WSL and Docker inherit Tailscale DNS at `100.100.100.100`. On this machine it returned only an IPv6 address for `http.kali.org`, while the Docker bridge had no usable IPv6 route. The build helper resolves the official Kali mirror names through an explicit IPv4-capable resolver and supplies those current mappings only to this build. It does not change Docker daemon DNS or interrupt other containers. APT still verifies Kali's signed repository metadata and fails closed if it is invalid.

## Verified build: 2026-07-17

- Local tag: `war-room/nmap-tcp:7.99`
- Immutable local image ID: `sha256:dca1d57e32c7818f6eadba39bcac1e31c6abfb57a2ae08b84b0062a8ab4dbde3`
- Installed packages: `nmap=7.99+dfsg-1kali1` and `nmap-common=7.99+dfsg-1kali1`
- Runtime configuration: user `65534:65534`, entrypoint `/usr/bin/nmap`
- Network-free restricted `nmap --version` proof: passed
- Repository digests: none, because the local-only image was deliberately not pushed to a registry

The executor contract accepts the exact local `sha256:` image ID as its immutable runtime reference. No certificate bypass, alternate package repository, floating runtime tag or fabricated digest was used.
