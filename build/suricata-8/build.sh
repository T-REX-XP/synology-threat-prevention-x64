#!/usr/bin/env bash
# Build Suricata for linux/amd64 via Docker (qemu on Apple Silicon).
# Version comes from repo-root VERSION.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${ROOT}/../.." && pwd)"
# shellcheck source=../../VERSION
. "${REPO}/VERSION"
: "${SURICATA_VERSION:?VERSION: missing SURICATA_VERSION}"

OUT="${ROOT}/out"
ARTIFACT="${REPO}/artifact"
TAG="tps-suricata:${SURICATA_VERSION}-amd64"
ARCHIVE="${ARTIFACT}/suricata-${SURICATA_VERSION}-linux-amd64.tar.gz"

mkdir -p "${OUT}" "${ARTIFACT}"

echo "==> docker build --platform linux/amd64 (Suricata ${SURICATA_VERSION})"
docker buildx build \
  --platform linux/amd64 \
  --build-arg "SURICATA_VERSION=${SURICATA_VERSION}" \
  --target export \
  --output "type=local,dest=${OUT}" \
  --tag "${TAG}" \
  --progress=plain \
  "${ROOT}"

echo "==> vendor Ubuntu libs + strip (DSM glibc 2.36)"
"${ROOT}/vendor-libs.sh"

tar -C "${OUT}" -czf "${ARCHIVE}" tps-suricata
echo "==> wrote ${ARCHIVE} (vendored + stripped — GitHub release asset)"
ls -lh "${ARCHIVE}" "${OUT}/tps-suricata/bin/suricata" 2>/dev/null || ls -lh "${OUT}"
if [[ -f "${OUT}/tps-suricata/build-info.txt" ]]; then
  echo "==> build-info"
  cat "${OUT}/tps-suricata/build-info.txt"
fi
