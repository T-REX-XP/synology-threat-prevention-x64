#!/usr/bin/env bash
# Vendor Ubuntu 24.04 amd64 shared libs (including glibc) next to Suricata
# so the binary can run on DSM 7.4 (glibc 2.36) without a Debian rebuild.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
ENGINE="${ROOT}/out/tps-suricata"
BIN="${ENGINE}/bin/suricata"
LIBDIR="${ENGINE}/lib"
INTERP_ON_NAS="/var/packages/ThreatPrevention/target/lib/ld-linux-x86-64.so.2"
RPATH_ON_NAS="/var/packages/ThreatPrevention/target/lib"

[ -x "${BIN}" ] || { echo "missing ${BIN}"; exit 1; }

echo "==> Collect runtime libs from ubuntu:24.04 linux/amd64 (cached, --pull never)"
docker run --rm --pull never --platform linux/amd64 \
  -v "${ENGINE}:/opt/tps-suricata" \
  ubuntu:24.04 bash -lc "
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq patchelf \
  liblz4-1 libmagic1 libcap-ng0 libnet1 \
  libnetfilter-queue1 libnfnetlink0 libmnl0 \
  libjansson4 libyaml-0-2 libpcre2-8-0 zlib1g \
  libhyperscan5 libpcap0.8 libstdc++6 \
  libbz2-1.0 liblzma5 >/dev/null
PREFIX=/opt/tps-suricata
BIN=\${PREFIX}/bin/suricata
LIBDIR=\${PREFIX}/lib
mkdir -p \"\${LIBDIR}\"

is_skip() {
  case \"\$1\" in
    linux-vdso.so.1) return 0 ;;
  esac
  return 1
}

todo=(\"\${BIN}\")
while [ \${#todo[@]} -gt 0 ]; do
  next=()
  for f in \"\${todo[@]}\"; do
    while read -r lib; do
      [ -n \"\${lib}\" ] || continue
      [ -f \"\${lib}\" ] || continue
      base=\$(basename \"\${lib}\")
      is_skip \"\${base}\" && continue
      dest=\"\${LIBDIR}/\${base}\"
      if [ ! -e \"\${dest}\" ]; then
        cp -aL \"\${lib}\" \"\${dest}\"
        next+=(\"\${dest}\")
      fi
    done < <(ldd \"\${f}\" 2>/dev/null | awk '/=> \\// { print \$3 } /^\\t\\// { print \$1 }')
  done
  todo=(\"\${next[@]}\")
done

# Dynamic linker + NSS helpers (not always in ldd NEEDED).
cp -aL /lib64/ld-linux-x86-64.so.2 \"\${LIBDIR}/ld-linux-x86-64.so.2\"
for nss in libnss_files.so.2 libnss_dns.so.2 libnss_compat.so.2; do
  if [ -f /lib/x86_64-linux-gnu/\$nss ]; then
    cp -aL /lib/x86_64-linux-gnu/\$nss \"\${LIBDIR}/\$nss\"
  fi
done

# Point the ELF interpreter at the DSM package path; rpath for the rest.
patchelf --set-interpreter '${INTERP_ON_NAS}' --set-rpath '\$ORIGIN/../lib' \"\${BIN}\"
for helper in suricatactl suricatasc; do
  if [ -f \"\${PREFIX}/bin/\${helper}\" ] && file \"\${PREFIX}/bin/\${helper}\" | grep -q ELF; then
    patchelf --set-interpreter '${INTERP_ON_NAS}' --set-rpath '\$ORIGIN/../lib' \"\${PREFIX}/bin/\${helper}\" || true
  fi
done
for so in \"\${LIBDIR}\"/*.so*; do
  [ -f \"\$so\" ] || continue
  case \"\$(basename \"\$so\")\" in
    ld-linux-x86-64.so.2) continue ;;
  esac
  patchelf --set-rpath '\$ORIGIN' \"\$so\" || true
done

echo '=== vendored ==='
ls -l \"\${LIBDIR}\"
echo '=== ldd suricata ==='
ldd \"\${BIN}\" || true
echo '=== interpreter ==='
readelf -l \"\${BIN}\" | grep interpreter || true
"

echo "==> Max GLIBC needed (should still be 2.39, satisfied by vendored libc)"
file "${BIN}"
ls -lh "${LIBDIR}" | head
