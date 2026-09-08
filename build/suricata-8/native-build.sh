#!/usr/bin/env bash
# Compile Suricata on this Linux host (no Docker). Used by GitHub Actions.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${ROOT}/../.." && pwd)"
# shellcheck source=../../VERSION
. "${REPO}/VERSION"
# shellcheck source=arch.sh
. "${ROOT}/arch.sh"

: "${SURICATA_VERSION:?VERSION: missing SURICATA_VERSION}"
TPS_ARCH="$(normalize_tps_arch "${TPS_ARCH:-$(uname -m)}")"
export TPS_ARCH

if [ "$(uname -s)" != Linux ]; then
    echo "ERROR: native build requires Linux (use --docker on macOS)" >&2
    exit 1
fi
HOST="$(normalize_tps_arch "$(uname -m)")"
if [ "${HOST}" != "${TPS_ARCH}" ]; then
    echo "ERROR: native build arch ${TPS_ARCH} != host ${HOST}; use --docker" >&2
    exit 1
fi

PREFIX="${ROOT}/out/tps-suricata"
SRC="${ROOT}/src/suricata-${SURICATA_VERSION}"
NJOBS="$(nproc 2>/dev/null || echo 2)"

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo "==> apt build deps (${TPS_ARCH})"
export DEBIAN_FRONTEND=noninteractive
${SUDO} apt-get update -qq
${SUDO} apt-get install -y -qq --no-install-recommends \
    build-essential autoconf automake libtool pkg-config \
    python3 python3-yaml python3-setuptools \
    libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev \
    zlib1g-dev libpcre2-dev libjansson-dev libmagic-dev \
    libcap-ng-dev liblz4-dev liblzma-dev \
    libnetfilter-queue-dev libnfnetlink-dev libmnl-dev \
    libnss3-dev libnspr4-dev \
    libhyperscan-dev \
    patchelf binutils file \
    wget ca-certificates curl \
    liblz4-1 libmagic1 libcap-ng0 libnet1 \
    libnetfilter-queue1 libnfnetlink0 libmnl0 \
    libjansson4 libpcre2-8-0 zlib1g \
    libhyperscan5 libpcap0.8 libstdc++6 \
    libbz2-1.0 >/dev/null

if ! command -v rustc >/dev/null 2>&1; then
    echo "==> rustup"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile minimal
fi
# shellcheck disable=SC1091
. "${HOME}/.cargo/env" 2>/dev/null || true
export PATH="${HOME}/.cargo/bin:${PATH}"

if [ ! -d "${SRC}" ]; then
    echo "==> fetch Suricata ${SURICATA_VERSION}"
    mkdir -p "${ROOT}/src"
    wget -q -O "${ROOT}/src/suricata-${SURICATA_VERSION}.tar.gz" \
        "https://www.openinfosecfoundation.org/download/suricata-${SURICATA_VERSION}.tar.gz"
    tar -xzf "${ROOT}/src/suricata-${SURICATA_VERSION}.tar.gz" -C "${ROOT}/src"
fi

rm -rf "${PREFIX}"
mkdir -p "${PREFIX}"

echo "==> configure + make (${TPS_ARCH})"
cd "${SRC}"
./configure \
    --prefix="${PREFIX}" \
    --sysconfdir="${PREFIX}/etc" \
    --localstatedir="${PREFIX}/var" \
    --enable-nfqueue \
    --disable-gccmarch-native
make -j"${NJOBS}"
make install

"${PREFIX}/bin/suricata" -V
(ldd "${PREFIX}/bin/suricata" || true) | tee "${PREFIX}/ldd.txt"
"${PREFIX}/bin/suricata" --build-info | tee "${PREFIX}/build-info.txt"
echo "native ${TPS_ARCH} $(uname -m)" | tee -a "${PREFIX}/build-info.txt"
