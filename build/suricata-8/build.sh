#!/usr/bin/env bash
# Build Suricata for linux/amd64 or linux/arm64.
# GitHub Actions: --native (no Docker). macOS: --docker (qemu).
# Version from repo-root VERSION. Arch from --arch / TPS_ARCH.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${ROOT}/../.." && pwd)"
# shellcheck source=../../VERSION
. "${REPO}/VERSION"
# shellcheck source=arch.sh
. "${ROOT}/arch.sh"
: "${SURICATA_VERSION:?VERSION: missing SURICATA_VERSION}"

NATIVE=""
DOCKER=""
TPS_ARCH="${TPS_ARCH:-}"

usage() {
    cat <<EOF
Usage: $0 [--arch x86_64|aarch64] [--native|--docker]

  --native   Compile on this Linux host (GitHub ubuntu-24.04 / ubuntu-24.04-arm)
  --docker   Cross-compile via Docker (needed on macOS)

Default: --native when Linux host arch matches; otherwise --docker.
EOF
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --arch)
            TPS_ARCH="$2"
            shift 2
            ;;
        --native) NATIVE=1; shift ;;
        --docker) DOCKER=1; shift ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

if [ -z "${TPS_ARCH}" ]; then
    if [ "$(uname -s)" = Linux ]; then
        TPS_ARCH="$(uname -m)"
    else
        TPS_ARCH=x86_64
    fi
fi
TPS_ARCH="$(normalize_tps_arch "${TPS_ARCH}")"
export TPS_ARCH

if [ -z "${NATIVE}" ] && [ -z "${DOCKER}" ]; then
    if [ "$(uname -s)" = Linux ] && [ "$(normalize_tps_arch "$(uname -m)")" = "${TPS_ARCH}" ]; then
        NATIVE=1
    else
        DOCKER=1
    fi
fi

OUT="${ROOT}/out"
ARTIFACT="${REPO}/artifact"
SUFFIX="$(arch_engine_suffix "${TPS_ARCH}")"
ARCHIVE="${ARTIFACT}/suricata-${SURICATA_VERSION}-${SUFFIX}.tar.gz"
mkdir -p "${OUT}" "${ARTIFACT}"

if [ "${NATIVE}" = 1 ]; then
    echo "==> native Suricata ${SURICATA_VERSION} (${TPS_ARCH})"
    "${ROOT}/native-build.sh"
else
    PLATFORM="$(arch_docker_platform "${TPS_ARCH}")"
    TAG="tps-suricata:${SURICATA_VERSION}-${TPS_ARCH}"
    echo "==> docker build --platform ${PLATFORM} (Suricata ${SURICATA_VERSION})"
    docker buildx build \
      --platform "${PLATFORM}" \
      --build-arg "SURICATA_VERSION=${SURICATA_VERSION}" \
      --target export \
      --output "type=local,dest=${OUT}" \
      --tag "${TAG}" \
      --progress=plain \
      "${ROOT}"
fi

echo "==> vendor libs + strip"
"${ROOT}/vendor-libs.sh"

tar -C "${OUT}" -czf "${ARCHIVE}" tps-suricata
echo "==> wrote ${ARCHIVE}"
ls -lh "${ARCHIVE}" "${OUT}/tps-suricata/bin/suricata" 2>/dev/null || ls -lh "${OUT}"
if [[ -f "${OUT}/tps-suricata/build-info.txt" ]]; then
    echo "==> build-info"
    cat "${OUT}/tps-suricata/build-info.txt"
fi
