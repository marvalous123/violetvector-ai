#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
base_image="kalilinux/kali-rolling@sha256:45eeb73d6f144a6a2fcf699b849c1d72ff5f2007ec952c98ab3084b77e9114a5"
image_tag="${WAR_ROOM_NMAP_IMAGE_TAG:-war-room/nmap-tcp:7.99}"
resolver="${WAR_ROOM_BUILD_DNS:-1.1.1.1}"

resolve_ipv4() {
  docker run --rm --dns "${resolver}" "${base_image}" \
    getent ahostsv4 "$1" |
    awk '$2 == "STREAM" { print $1; exit }'
}

http_kali_ip="$(resolve_ipv4 http.kali.org)"
kali_download_ip="$(resolve_ipv4 kali.download)"

if [[ ! "${http_kali_ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] ||
   [[ ! "${kali_download_ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Could not obtain IPv4 addresses for the signed Kali repositories." >&2
  exit 1
fi

docker build \
  --no-cache \
  --add-host "http.kali.org:${http_kali_ip}" \
  --add-host "kali.download:${kali_download_ip}" \
  --tag "${image_tag}" \
  --file "${script_dir}/Dockerfile" \
  "${script_dir}"

docker run --rm \
  --network none \
  --pull never \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 256m \
  --cpus 1 \
  --pids-limit 64 \
  --user 65534:65534 \
  "${image_tag}" \
  --version

docker run --rm \
  --network none \
  --pull never \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --memory 256m \
  --cpus 1 \
  --pids-limit 64 \
  --entrypoint /usr/bin/dpkg-query \
  "${image_tag}" \
  -W nmap nmap-common

docker image inspect "${image_tag}" \
  --format 'Immutable local image ID: {{.Id}}'
