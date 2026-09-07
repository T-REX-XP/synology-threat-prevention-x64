#!/usr/bin/env bash
# Pack a DSM 7 x86_64 SPK the same way synology_codecs does.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/spk/src/threatprevention"
ENGINE="${ROOT}/build/suricata-8/out/tps-suricata"
ORIG_RULES="${ROOT}/unpacked/package/etc/rules"
ORIG_SPK="${ROOT}/unpacked/spk"
STAGING="${ROOT}/build/spk/staging"
OUT_DIR="${ROOT}/artifact"
PKG_VER="$(grep '^version=' "${SRC}/INFO" | cut -d= -f2 | tr -d '"')"
SPK_NAME="ThreatPrevention-x86_64-${PKG_VER}.spk"

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

[ -x "${ENGINE}/bin/suricata" ] || die "Missing ${ENGINE}/bin/suricata — run build/suricata-8/build.sh first"
[ -f "${ORIG_RULES}/emerging.rules.tar.gz" ] || die "Missing original rules tarball"
[ -d "${SRC}" ] || die "Missing SPK sources in ${SRC}"

if [ ! -f "${ENGINE}/lib/ld-linux-x86-64.so.2" ]; then
  info "Vendor Ubuntu 24.04 libs (DSM glibc is 2.36; binary needs 2.39)"
  "${ROOT}/build/suricata-8/vendor-libs.sh"
fi

rm -rf "${STAGING}"
mkdir -p "${STAGING}/package" "${OUT_DIR}"

info "Stage Suricata 8.0.6 engine"
mkdir -p "${STAGING}/package/bin" "${STAGING}/package/lib" "${STAGING}/package/share"
cp -a "${ENGINE}/bin/." "${STAGING}/package/bin/"
cp -a "${ENGINE}/lib/." "${STAGING}/package/lib/"
cp -a "${ENGINE}/share/." "${STAGING}/package/share/"
cp -a "${ENGINE}/build-info.txt" "${STAGING}/package/" 2>/dev/null || true
cp -a "${ENGINE}/ldd.txt" "${STAGING}/package/" 2>/dev/null || true

info "Stage tps python (ingest / compiler / tpsweb)"
mkdir -p "${STAGING}/package/lib/tps"
cp -a "${SRC}/python/." "${STAGING}/package/lib/tps/"

info "Strip linux/amd64 binaries (keep original engine tree unstripped)"
if command -v docker >/dev/null 2>&1; then
  docker run --rm --pull never --platform linux/amd64 \
    -v "${STAGING}/package/bin:/b" \
    ubuntu:24.04 bash -lc 'apt-get update -qq && apt-get install -y -qq binutils >/dev/null && strip /b/suricata /b/suricatactl /b/suricatasc || true' \
    || info "strip skipped (docker image missing)"
fi

info "Stage original portable rules and policy"
mkdir -p "${STAGING}/package/etc/rules" "${STAGING}/package/etc/suricata" "${STAGING}/package/etc/sensor"
cp -a "${ORIG_RULES}/emerging.rules.tar.gz" "${STAGING}/package/etc/rules/"
cp -a "${ORIG_RULES}/signature.conf" "${STAGING}/package/etc/rules/"
cp -a "${ORIG_RULES}/classification.config" "${STAGING}/package/etc/rules/"
cp -a "${ORIG_RULES}/reference.config" "${STAGING}/package/etc/rules/"
cp -a "${ORIG_RULES}/syno-custom-events.rules" "${STAGING}/package/etc/rules/"
cp -a "${ORIG_RULES}/version.txt" "${STAGING}/package/etc/rules/" 2>/dev/null || true
cp -a "${ROOT}/unpacked/package/etc/suricata/threshold.config" "${STAGING}/package/etc/suricata/"
cp -a "${SRC}/package/etc/sensor/sensor.conf" "${STAGING}/package/etc/sensor/sensor.conf"
cp -a "${SRC}/package/etc/suricata/suricata.yaml" "${STAGING}/package/etc/suricata/suricata.yaml"

info "Stage official ExtJS UI (research PoC — not redistributable)"
OFFICIAL_UI="${ROOT}/unpacked/package/ui"
[ -f "${OFFICIAL_UI}/synoips.js" ] || die "Official UI missing at ${OFFICIAL_UI}/synoips.js"
rm -rf "${STAGING}/package/ui"
mkdir -p "${STAGING}/package/ui"
cp -a "${OFFICIAL_UI}/." "${STAGING}/package/ui/"
cp -a "${SRC}/package/ui/tps-bridge.js" "${STAGING}/package/ui/tps-bridge.js"
python3 - "${STAGING}/package/ui/config" <<'PY'
import json, sys
path = sys.argv[1]
cfg = json.load(open(path, encoding="utf-8"))
app = cfg["synoips.js"]["SYNO.SDS.TPS.Application"]
deps = list(app.get("depend") or [])
if "SYNO.SDS.TPS.Bridge" not in deps:
    deps = ["SYNO.SDS.TPS.Bridge"] + deps
app["depend"] = deps
merged = {
    "tps-bridge.js": {
        "SYNO.SDS.TPS.Bridge": {
            "type": "lib",
            "title": "TPS Suricata compatibility",
            "formatedTitle": "TPS Suricata compatibility",
        },
        "SYNO.SDS.ThreatPrevention.Application": {
            "type": "app",
            "appWindow": "SYNO.SDS.TPS.MainWindow",
            "title": "Threat Prevention",
            "formatedTitle": "Threat Prevention",
            "icon": "images/IDS_IPS_{0}.png",
            "allUsers": False,
            "maxInstance": 1,
            "depend": ["SYNO.SDS.TPS.Bridge", "SYNO.SDS.TPS.MainWindow"],
        },
    }
}
merged.update(cfg)
json.dump(merged, open(path, "w", encoding="utf-8"), indent=2)
print("merged official ui/config with tps-bridge.js")
PY
# DSM tile sizes official tree may omit
if command -v sips >/dev/null 2>&1 && [ -f "${STAGING}/package/ui/images/IDS_IPS_256.png" ]; then
  for sz in 16 32; do
    if [ ! -f "${STAGING}/package/ui/images/IDS_IPS_${sz}.png" ]; then
      sips -z "${sz}" "${sz}" "${STAGING}/package/ui/images/IDS_IPS_256.png" \
        --out "${STAGING}/package/ui/images/IDS_IPS_${sz}.png" >/dev/null
    fi
  done
fi

info "Stage SYNO.TPS.lib (Info listing only; aarch64 .so are not packed)"
mkdir -p "${STAGING}/package/webapi"
cp -a "${ROOT}/unpacked/package/webapi/SYNO.TPS.lib" "${STAGING}/package/webapi/SYNO.TPS.lib"

info "Compute extractsize"
EXTRACT_KB="$(du -sk "${STAGING}/package" | awk '{print $1}')"

info "Write INFO"
{
  cat "${SRC}/INFO"
  echo "extractsize=\"${EXTRACT_KB}\""
  echo "create_time=\"$(date -u +%Y%m%d-%H:%M:%S)\""
} > "${STAGING}/INFO"

info "Icons, scripts, conf"
cp -a "${ORIG_SPK}/PACKAGE_ICON.PNG" "${STAGING}/PACKAGE_ICON.PNG"
cp -a "${ORIG_SPK}/PACKAGE_ICON_256.PNG" "${STAGING}/PACKAGE_ICON_256.PNG"
mkdir -p "${STAGING}/scripts" "${STAGING}/conf"
cp -a "${SRC}/scripts/." "${STAGING}/scripts/"
chmod +x "${STAGING}/scripts/"*
cp -a "${SRC}/conf/." "${STAGING}/conf/"

info "package.tgz"
export COPYFILE_DISABLE=1
tar czf "${STAGING}/package.tgz" -C "${STAGING}/package" .
rm -rf "${STAGING}/package"

info "SPK tar (unsigned)"
(cd "${STAGING}" && tar cf "${OUT_DIR}/${SPK_NAME}" \
  package.tgz INFO PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG scripts conf)

info "Built ${OUT_DIR}/${SPK_NAME}"
tar tf "${OUT_DIR}/${SPK_NAME}"
ls -lh "${OUT_DIR}/${SPK_NAME}"
file "${OUT_DIR}/${SPK_NAME}"
