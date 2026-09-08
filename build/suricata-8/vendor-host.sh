#!/usr/bin/env bash
# Vendor libc + runtime .so next to Suricata and patchelf the NAS interpreter.
# Runs on the build host (GitHub Actions / native Linux). No Docker.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=arch.sh
. "${ROOT}/arch.sh"

PREFIX="${1:-${ROOT}/out/tps-suricata}"
TPS_ARCH="$(normalize_tps_arch "${TPS_ARCH:-$(uname -m)}")"
BIN="${PREFIX}/bin/suricata"
LIBDIR="${PREFIX}/lib"
LOADER_NAME="$(arch_loader_name "${TPS_ARCH}")"
LOADER_SRC="$(arch_loader_path "${TPS_ARCH}")"
GNU_LIBDIR="$(arch_gnu_libdir "${TPS_ARCH}")"
INTERP_ON_NAS="$(arch_interp_on_nas "${TPS_ARCH}")"

[ -x "${BIN}" ] || { echo "missing ${BIN}" >&2; exit 1; }

if [ -f "${LIBDIR}/${LOADER_NAME}" ]; then
    echo "==> already vendored (${LIBDIR}/${LOADER_NAME})"
    exit 0
fi

command -v patchelf >/dev/null || { echo "missing patchelf" >&2; exit 1; }
mkdir -p "${LIBDIR}"

is_skip() {
    case "$1" in
        linux-vdso.so.1|linux-vdso.so.1.*) return 0 ;;
    esac
    return 1
}

todo=("${BIN}")
while [ "${#todo[@]}" -gt 0 ]; do
    next=()
    for f in "${todo[@]}"; do
        while read -r lib; do
            [ -n "${lib}" ] || continue
            [ -f "${lib}" ] || continue
            base="$(basename "${lib}")"
            is_skip "${base}" && continue
            dest="${LIBDIR}/${base}"
            if [ ! -e "${dest}" ]; then
                cp -aL "${lib}" "${dest}"
                next+=("${dest}")
            fi
        done < <(ldd "${f}" 2>/dev/null | awk '/=> \// { print $3 } /^\t\// { print $1 }')
    done
    todo=("${next[@]}")
done

[ -f "${LOADER_SRC}" ] || { echo "dynamic linker not found: ${LOADER_SRC}" >&2; exit 1; }
cp -aL "${LOADER_SRC}" "${LIBDIR}/${LOADER_NAME}"

for nss in libnss_files.so.2 libnss_dns.so.2 libnss_compat.so.2; do
    if [ -f "${GNU_LIBDIR}/${nss}" ]; then
        cp -aL "${GNU_LIBDIR}/${nss}" "${LIBDIR}/${nss}"
    fi
done

patchelf --set-interpreter "${INTERP_ON_NAS}" --set-rpath "${INTERP_ON_NAS%/*}" "${BIN}"
for helper in suricatactl suricatasc; do
    if [ -f "${PREFIX}/bin/${helper}" ] && file "${PREFIX}/bin/${helper}" | grep -q ELF; then
        patchelf --set-interpreter "${INTERP_ON_NAS}" --set-rpath "${INTERP_ON_NAS%/*}" "${PREFIX}/bin/${helper}" || true
    fi
done
for so in "${LIBDIR}"/*.so*; do
    [ -f "${so}" ] || continue
    case "$(basename "${so}")" in
        "${LOADER_NAME}") continue ;;
    esac
    patchelf --set-rpath '$ORIGIN' "${so}" || true
done

echo "=== vendored (${TPS_ARCH}) ==="
ls -l "${LIBDIR}"
echo "=== ldd suricata ==="
ldd "${BIN}" || true
echo "=== interpreter ==="
readelf -l "${BIN}" | grep interpreter || true

if command -v strip >/dev/null; then
    strip --strip-unneeded "${BIN}" || true
    for helper in suricatactl suricatasc; do
        if [ -f "${PREFIX}/bin/${helper}" ] && file "${PREFIX}/bin/${helper}" | grep -q ELF; then
            strip --strip-unneeded "${PREFIX}/bin/${helper}" || true
        fi
    done
fi
echo "=== stripped ==="
ls -lh "${BIN}" "${PREFIX}/bin/suricatactl" "${PREFIX}/bin/suricatasc" 2>/dev/null || true
