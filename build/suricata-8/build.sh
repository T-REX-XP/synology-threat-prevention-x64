#!/usr/bin/env bash
# Build Suricata 8.0.6 for linux/amd64 via Docker (qemu on Apple Silicon).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${ROOT}/../.." && pwd)"
OUT="${ROOT}/out"
ARTIFACT="${REPO}/artifact"
TAG="tps-suricata:8.0.6-amd64"

mkdir -p "${OUT}" "${ARTIFACT}"

echo "==> docker build --platform linux/amd64 (Suricata 8.0.6)"
docker buildx build \
  --platform linux/amd64 \
  --target export \
  --output "type=local,dest=${OUT}" \
  --tag "${TAG}" \
  --progress=plain \
  "${ROOT}"

echo "==> vendor Ubuntu libs + strip (DSM glibc 2.36)"
"${ROOT}/vendor-libs.sh"

ARCHIVE="${ARTIFACT}/suricata-8.0.6-linux-amd64.tar.gz"
tar -C "${OUT}" -czf "${ARCHIVE}" tps-suricata
echo "==> wrote ${ARCHIVE} (vendored + stripped — GitHub release asset)"
ls -lh "${ARCHIVE}" "${OUT}/tps-suricata/bin/suricata" 2>/dev/null || ls -lh "${OUT}"
if [[ -f "${OUT}/tps-suricata/build-info.txt" ]]; then
  echo "==> build-info"
  cat "${OUT}/tps-suricata/build-info.txt"
fi
