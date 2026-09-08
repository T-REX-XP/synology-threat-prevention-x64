#!/usr/bin/env bash
# Vendor runtime libs next to Suricata.
# Native when host arch matches TPS_ARCH (GitHub Actions). Docker only to
# cross-compile from a mismatched host (e.g. Apple Silicon → x86_64).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=arch.sh
. "${ROOT}/arch.sh"

ENGINE="${ROOT}/out/tps-suricata"
TPS_ARCH="$(normalize_tps_arch "${TPS_ARCH:-$(uname -m)}")"
HOST_ARCH="$(normalize_tps_arch "$(uname -m)" 2>/dev/null || uname -m)"
export TPS_ARCH

[ -x "${ENGINE}/bin/suricata" ] || { echo "missing ${ENGINE}/bin/suricata" >&2; exit 1; }

if [ "$(uname -s)" = Linux ] && [ "${HOST_ARCH}" = "${TPS_ARCH}" ]; then
    echo "==> vendor libs on host (${TPS_ARCH}, no Docker)"
    exec "${ROOT}/vendor-host.sh" "${ENGINE}"
fi

PLATFORM="$(arch_docker_platform "${TPS_ARCH}")"
echo "==> vendor libs via docker --platform ${PLATFORM}"
docker run --rm --pull missing --platform "${PLATFORM}" \
    -e TPS_ARCH="${TPS_ARCH}" \
    -v "${ROOT}:/opt/tps-build:ro" \
    -v "${ENGINE}:/opt/tps-suricata" \
    ubuntu:24.04 bash -lc '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq patchelf binutils \
  liblz4-1 libmagic1 libcap-ng0 libnet1 \
  libnetfilter-queue1 libnfnetlink0 libmnl0 \
  libjansson4 libyaml-0-2 libpcre2-8-0 zlib1g \
  libhyperscan5 libpcap0.8 libstdc++6 \
  libbz2-1.0 liblzma5 file >/dev/null
export TPS_ARCH
/opt/tps-build/vendor-host.sh /opt/tps-suricata
'

echo "==> vendored libc satisfies DSM via package-local interpreter"
file "${ENGINE}/bin/suricata"
ls -lh "${ENGINE}/lib" | head
