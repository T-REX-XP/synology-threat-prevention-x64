#!/bin/bash
# Copy Suricata's non-system shared libraries into $PREFIX/lib and set rpath.
set -euo pipefail
PREFIX="${1:?prefix}"
BIN="${PREFIX}/bin/suricata"
LIBDIR="${PREFIX}/lib"
mkdir -p "${LIBDIR}"

is_system() {
	case "$1" in
		libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1| \
		ld-linux-x86-64.so.2|ld-linux-aarch64.so.1|libgcc_s.so.1|libstdc++.so.6| \
		libresolv.so.2|libnss_files.so.2|libnss_dns.so.2)
			return 0 ;;
	esac
	return 1
}

todo=("${BIN}")
while ((${#todo[@]})); do
	next=()
	for f in "${todo[@]}"; do
		while read -r lib; do
			[ -n "${lib}" ] || continue
			[ -f "${lib}" ] || continue
			base="$(basename "${lib}")"
			if is_system "${base}"; then
				continue
			fi
			dest="${LIBDIR}/${base}"
			if [ ! -e "${dest}" ]; then
				cp -aL "${lib}" "${dest}"
				next+=("${dest}")
			fi
		done < <(ldd "${f}" 2>/dev/null | awk '/=> \// { print $3 }')
	done
	todo=("${next[@]}")
done

# $ORIGIN is ignored when the binary has file capabilities (AT_SECURE).
# Use the NAS install path so setcap + package user can still load liblz4.
patchelf --set-rpath /var/packages/ThreatPrevention/target/lib "${BIN}"
for so in "${LIBDIR}"/*.so*; do
	[ -f "${so}" ] || continue
	patchelf --set-rpath '$ORIGIN' "${so}" || true
done

echo "Vendored into ${LIBDIR}:"
ls -l "${LIBDIR}"
echo "NEEDED after patchelf:"
ldd "${BIN}"
