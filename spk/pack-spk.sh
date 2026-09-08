#!/usr/bin/env bash
# Assemble the unsigned DSM 7 SPK. Called by ./build.sh (preferred).
# Official UI/rules/icons come from TPS_OFFICIAL (build/official/), never from git.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../VERSION
. "${ROOT}/VERSION"
: "${SURICATA_VERSION:?VERSION: missing SURICATA_VERSION}"
: "${PKG_RELEASE:?VERSION missing PKG_RELEASE}"
PKG_VERSION="${SURICATA_VERSION}-${PKG_RELEASE}"
ENGINE_ASSET="suricata-${SURICATA_VERSION}-linux-amd64.tar.gz"

SRC="${ROOT}/spk/src/threatprevention"
ENGINE="${ROOT}/build/suricata-8/out/tps-suricata"
STAGING="${ROOT}/build/spk/staging"
OUT_DIR="${ROOT}/artifact"
PKG_VER="${PKG_VERSION}"
SPK_NAME="ThreatPrevention-x86_64-${PKG_VER}.spk"

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

resolve_official() {
  local candidates=()
  [ -n "${TPS_OFFICIAL:-}" ] && candidates+=("${TPS_OFFICIAL}")
  candidates+=("${ROOT}/build/official" "${ROOT}/unpacked")
  local d
  for d in "${candidates[@]}"; do
    if [ -f "${d}/package/ui/synoips.js" ] \
      && [ -f "${d}/package/etc/rules/emerging.rules.tar.gz" ] \
      && [ -f "${d}/spk/PACKAGE_ICON.PNG" ]; then
      OFFICIAL="$d"
      ORIG_RULES="${OFFICIAL}/package/etc/rules"
      ORIG_SPK="${OFFICIAL}/spk"
      info "Official inputs: ${OFFICIAL}"
      return
    fi
  done
  die "Official Synology tree missing. Run ./build.sh (downloads ThreatPrevention 1.3.3-0926 into build/official/). Do not commit that tree."
}

resolve_official
[ -x "${ENGINE}/bin/suricata" ] || die "Missing ${ENGINE}/bin/suricata — run ./build.sh (or build/suricata-8/build.sh)"
[ -f "${ORIG_RULES}/emerging.rules.tar.gz" ] || die "Missing original rules tarball under ${ORIG_RULES}"
[ -d "${SRC}" ] || die "Missing SPK sources in ${SRC}"

if [ ! -f "${ENGINE}/lib/ld-linux-x86-64.so.2" ]; then
  info "Vendor Ubuntu 24.04 libs (DSM glibc is 2.36; binary needs 2.39)"
    command -v docker >/dev/null 2>&1 \
      || die "Engine tarball is missing vendored libs and Docker is not available. Use a GitHub release ${ENGINE_ASSET} or run ./build.sh on a Docker host."
  "${ROOT}/build/suricata-8/vendor-libs.sh"
fi

rm -rf "${STAGING}"
mkdir -p "${STAGING}/package" "${OUT_DIR}"

info "Stage Suricata ${SURICATA_VERSION} engine"
mkdir -p "${STAGING}/package/bin" "${STAGING}/package/lib" "${STAGING}/package/share"
cp -a "${ENGINE}/bin/." "${STAGING}/package/bin/"
cp -a "${ENGINE}/lib/." "${STAGING}/package/lib/"
cp -a "${ENGINE}/share/." "${STAGING}/package/share/"
cp -a "${ENGINE}/build-info.txt" "${STAGING}/package/" 2>/dev/null || true
cp -a "${ENGINE}/ldd.txt" "${STAGING}/package/" 2>/dev/null || true

info "Stage tps python (ingest / compiler / tpsweb)"
mkdir -p "${STAGING}/package/lib/tps"
cp -a "${SRC}/python/." "${STAGING}/package/lib/tps/"
rm -f "${STAGING}/package/lib/tps/test_"*.py "${STAGING}/package/lib/tps/"*.pyc

info "Stage PyYAML for suricata-update (DSM python3 has none)"
[ -f "${SRC}/vendor/yaml/__init__.py" ] || die "Missing ${SRC}/vendor/yaml — vendored PyYAML"
mkdir -p "${STAGING}/package/lib/python"
cp -a "${SRC}/vendor/yaml" "${STAGING}/package/lib/python/yaml"
cp -a "${SRC}/vendor/PyYAML.LICENSE" "${STAGING}/package/lib/python/PyYAML.LICENSE" 2>/dev/null || true

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
cp -a "${OFFICIAL}/package/etc/suricata/threshold.config" "${STAGING}/package/etc/suricata/"
cp -a "${SRC}/package/etc/sensor/sensor.conf" "${STAGING}/package/etc/sensor/sensor.conf"
cp -a "${SRC}/package/etc/suricata/suricata.yaml" "${STAGING}/package/etc/suricata/suricata.yaml"
cp -a "${SRC}/package/etc/mirror.conf" "${STAGING}/package/etc/mirror.conf"
cp -a "${SRC}/package/etc/accel.conf" "${STAGING}/package/etc/accel.conf"
cp -a "${SRC}/package/etc/rule-sources.json" "${STAGING}/package/etc/rule-sources.json"
mkdir -p "${STAGING}/package/etc/openwrt" "${STAGING}/package/etc/mikrotik"
cp -a "${SRC}/package/etc/openwrt/." "${STAGING}/package/etc/openwrt/"
cp -a "${SRC}/package/etc/mikrotik/." "${STAGING}/package/etc/mikrotik/"
chmod +x "${STAGING}/package/etc/openwrt/apply-tps-mirror.sh" 2>/dev/null || true
mkdir -p "${STAGING}/package/etc/nginx"
cp -a "${SRC}/package/etc/nginx/dsm-tpsweb.conf" "${STAGING}/package/etc/nginx/dsm-tpsweb.conf"

info "Stage official ExtJS UI (research PoC — not redistributable)"
OFFICIAL_UI="${OFFICIAL}/package/ui"
[ -f "${OFFICIAL_UI}/synoips.js" ] || die "Official UI missing at ${OFFICIAL_UI}/synoips.js"
rm -rf "${STAGING}/package/ui"
mkdir -p "${STAGING}/package/ui"
cp -a "${OFFICIAL_UI}/." "${STAGING}/package/ui/"
# One JS file only. Registering bridge files as ui/config modules makes DSM
# JSLoad a cycle (synoips.js ↔ Bridge) and AppLaunch dies with "loop detected".
BRIDGE="${SRC}/package/ui/bridge"
{
  printf '%s\n' "/* tps-bridge inlined — do not add ui/bridge/*.js to ui/config */"
  cat "${BRIDGE}/transport.js"
  printf '\n'
  cat "${BRIDGE}/dsm7.js"
  printf '\n'
  cat "${BRIDGE}/settings-inject.js"
  printf '\n'
  cat "${STAGING}/package/ui/synoips.js"
} > "${STAGING}/package/ui/synoips.js.new"
mv "${STAGING}/package/ui/synoips.js.new" "${STAGING}/package/ui/synoips.js"
cp -a "${SRC}/package/ui/tps-chart.js" "${STAGING}/package/ui/tps-chart.js"
rm -rf "${STAGING}/package/ui/bridge"
rm -f "${STAGING}/package/ui/tps-bridge.js" \
  "${STAGING}/package/ui/threatprevention.js" \
  "${STAGING}/package/ui/index.html" \
  "${STAGING}/package/ui/app.js" \
  "${STAGING}/package/ui/app.css"
python3 - "${STAGING}/package/ui/config" "${PKG_VER}" <<'PY'
import json, sys
path, ver = sys.argv[1], sys.argv[2]
cfg = json.load(open(path, encoding="utf-8"))
cfg.pop("tps-bridge.js", None)
cfg.pop("threatprevention.js", None)
# Official Trends/TopN depend on SYNO.SDS.Chart.* (SRM desktop). Register
# stubs as their own module so JSLoad defines LineChart before Overview runs.
# Do not put these keys on synoips.js — a second define of Application-adjacent
# names on tps-bridge.js previously caused a JSLoad cycle.
cfg["tps-chart.js"] = {
    "SYNO.SDS.Chart.LineChart": {"type": "lib", "depend": []},
    "SYNO.SDS.Chart.PieChart": {"type": "lib", "depend": []},
    "SYNO.SDS.Chart.CreateAxis": {"type": "lib", "depend": []},
}
app = cfg["synoips.js"]["SYNO.SDS.TPS.Application"]
app["depend"] = [d for d in (app.get("depend") or []) if d != "SYNO.SDS.TPS.Bridge"]
for extra in ("SYNO.SDS.Chart.LineChart", "SYNO.SDS.Chart.PieChart"):
    if extra not in app["depend"]:
        app["depend"].insert(0, extra)
# Bust DSM/browser cache of synoips.js?v=1.3.3-0926
app["version"] = ver
cfg["synoips.js"].pop("SYNO.SDS.ThreatPrevention.Application", None)
json.dump(cfg, open(path, "w", encoding="utf-8"), indent=2)
print("ui/config modules:", list(cfg))
print("apps:", [k for k, v in cfg["synoips.js"].items() if isinstance(v, dict) and v.get("type") == "app"])
print("app version:", app.get("version"))
print("official depend:", app.get("depend"))
PY
info "DSM Help (helptoc + community pages + empty indexdb)"
HELP_DIR="${SRC}/package/ui/help/enu"
[ -f "${HELP_DIR}/threatprevention_dsm.html" ] || die "Missing ${HELP_DIR}/threatprevention_dsm.html"
python3 - "${STAGING}/package/ui" "${HELP_DIR}" <<'PY'
import json, os, shutil, sys
ui, src_dir = sys.argv[1], sys.argv[2]
pages = [
    ("threatprevention_dsm.html", "This NAS (Suricata IDS)"),
]
help_root = os.path.join(ui, "help")
for name, _title in pages:
    src = os.path.join(src_dir, name)
    if not os.path.isfile(src):
        raise SystemExit("missing " + src)
    img_src = os.path.join(src_dir, "images")
    for lang in sorted(os.listdir(help_root)):
        dest = os.path.join(help_root, lang)
        if os.path.isdir(dest):
            shutil.copy(src, os.path.join(dest, name))
            if os.path.isdir(img_src):
                img_dest = os.path.join(dest, "images")
                os.makedirs(img_dest, exist_ok=True)
                for fn in os.listdir(img_src):
                    if fn.startswith("."):
                        continue
                    shutil.copy(os.path.join(img_src, fn), os.path.join(img_dest, fn))
toc_path = os.path.join(ui, "helptoc.conf")
toc = json.load(open(toc_path, encoding="utf-8"))
children = toc.get("toc") or []
existing = {c.get("content") for c in children}
insert_at = 0
for name, title in pages:
    if name in existing:
        continue
    children.insert(insert_at, {"title": title, "content": name})
    insert_at += 1
toc["toc"] = children
json.dump(toc, open(toc_path, "w", encoding="utf-8"), indent="\t")
print("helptoc.conf topics:", [c.get("content") for c in children])
htoc = os.path.join(ui, ".helptoc", "SYNO.SDS.TPS.Application")
if os.path.isdir(htoc):
    for fname in os.listdir(htoc):
        path = os.path.join(htoc, fname)
        try:
            data = json.load(open(path, encoding="utf-8"))
        except ValueError:
            continue
        kids = data.get("children") or []
        have = {k.get("topic") for k in kids}
        insert_at = 0
        for name, title in pages:
            if name in have:
                continue
            kids.insert(insert_at, {
                "id": "SYNO.SDS.TPS.Application:" + name,
                "base": "help",
                "topic": name,
                "text": title,
                "leaf": True,
            })
            insert_at += 1
        data["children"] = kids
        json.dump(data, open(path, "w", encoding="utf-8"), separators=(",", ":"))
idx_path = os.path.join(ui, "index.conf")
idx = json.load(open(idx_path, encoding="utf-8"))
keys = list(idx.get("keywords") or [])
for extra in (
    "suricata", "ids", "emerging threats",
    "hyperscan", "intel", "dpdk",
):
    if extra not in keys:
        keys.append(extra)
idx["keywords"] = keys
json.dump(idx, open(idx_path, "w", encoding="utf-8"), indent="\t")
print("index keywords:", keys)
PY
mkdir -p "${STAGING}/package/indexdb/helpindexdb" "${STAGING}/package/indexdb/appindexdb"
touch "${STAGING}/package/indexdb/helpindexdb/.keep" "${STAGING}/package/indexdb/appindexdb/.keep"
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
cp -a "${OFFICIAL}/package/webapi/SYNO.TPS.lib" "${STAGING}/package/webapi/SYNO.TPS.lib"

info "Compute extractsize"
EXTRACT_KB="$(du -sk "${STAGING}/package" | awk '{print $1}')"

info "Write INFO"
{
  sed \
    -e "s/^version=.*/version=\"${PKG_VERSION}\"/" \
    -e "s/vanilla Suricata [0-9][0-9.]*/vanilla Suricata ${SURICATA_VERSION}/" \
    "${SRC}/INFO"
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
export COPY_EXTENDED_ATTRIBUTES_DISABLE=1
if command -v xattr >/dev/null 2>&1; then
  xattr -cr "${STAGING}" 2>/dev/null || true
fi
tar --format ustar -czf "${STAGING}/package.tgz" -C "${STAGING}/package" .
rm -rf "${STAGING}/package"

info "SPK tar (unsigned)"
if command -v xattr >/dev/null 2>&1; then
  xattr -cr "${STAGING}" 2>/dev/null || true
fi
(cd "${STAGING}" && tar --format ustar -cf "${OUT_DIR}/${SPK_NAME}" \
  package.tgz INFO PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG scripts conf)

info "Built ${OUT_DIR}/${SPK_NAME}"
tar tf "${OUT_DIR}/${SPK_NAME}"
ls -lh "${OUT_DIR}/${SPK_NAME}"
file "${OUT_DIR}/${SPK_NAME}"
