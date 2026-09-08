#!/usr/bin/env bash
# Build a DSM 7 x86_64 Threat Prevention PoC SPK from scratch.
#
# Community sources live in this repo. Official Synology ExtJS UI, icons,
# bootstrap ET tarball, and SYNO.TPS.lib are downloaded at build time from the
# public Package Center SPK and never stored in git.
#
# Unlike synology_codecs, this script does not decrypt SPKs or patch binaries.
# The SRM Threat Prevention package is a signed POSIX tar. Closed aarch64
# engines (.so / synosuricata) are discarded; Suricata 8 is built from source.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/spk/src/threatprevention"
CACHE_DIR="${SCRIPT_DIR}/build/cache"
OFFICIAL_DIR="${SCRIPT_DIR}/build/official"
OUT_DIR="${SCRIPT_DIR}/artifact"

# Official SRM package used only as a UI / policy / bootstrap-rules source.
OFFICIAL_PKG="ThreatPrevention"
OFFICIAL_VER="1.3.3-0926"
OFFICIAL_ARCH="cypress"
OFFICIAL_SPK_NAME="${OFFICIAL_PKG}-${OFFICIAL_ARCH}-${OFFICIAL_VER}.spk"

SKIP_ENGINE=0
SKIP_TESTS=0
FORCE_EXTRACT=0
OFFICIAL_SPK_OVERRIDE=""

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

usage() {
    cat <<EOF
Usage: $0 [options]

Build an unsigned DSM 7 x86_64 ThreatPrevention SPK.

  --skip-engine         Reuse build/suricata-8/out (do not run Docker)
  --skip-tests          Do not run python/test_compat.py
  --official-spk PATH   Use this official .spk instead of downloading
  --force               Re-extract official files even if build/official exists
  -h, --help            Show this help

Default: download ${OFFICIAL_SPK_NAME}, extract proprietary inputs into
build/official/, compile Suricata 8 via Docker, pack artifact/*.spk.
EOF
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-engine) SKIP_ENGINE=1; shift ;;
        --skip-tests) SKIP_TESTS=1; shift ;;
        --force) FORCE_EXTRACT=1; shift ;;
        --official-spk)
            [ $# -ge 2 ] || usage
            OFFICIAL_SPK_OVERRIDE="$2"
            shift 2
            ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

check_deps() {
    local missing=()
    for cmd in tar curl python3; do
        command -v "$cmd" >/dev/null || missing+=("$cmd")
    done
    if [ "$SKIP_ENGINE" -eq 0 ]; then
        command -v docker >/dev/null || missing+=("docker")
    fi
    if [ ${#missing[@]} -gt 0 ]; then
        die "Missing required tools: ${missing[*]}"
    fi
    [ -d "$SRC_DIR" ] || die "Missing community sources at ${SRC_DIR}"
}

# Reject Synology encrypted SPKs (keytype 3). This PoC only accepts the
# public POSIX-tar package from Package Center.
assert_plain_spk() {
    local spk="$1"
    python3 - "$spk" <<'PY'
import sys
path = sys.argv[1]
with open(path, "rb") as f:
    magic = f.read(4)
if len(magic) < 4:
    sys.exit("SPK is empty or unreadable")
if (int.from_bytes(magic, "big") & 0xFFFFFF) == 0xADBEEF:
    sys.exit(
        "Encrypted Synology SPK (not supported). "
        "Use the public Package Center tar from archive/global download."
    )
PY
}

official_complete() {
    local root="$1"
    [ -f "${root}/package/ui/synoips.js" ] || return 1
    [ -f "${root}/package/etc/rules/emerging.rules.tar.gz" ] || return 1
    [ -f "${root}/package/etc/rules/signature.conf" ] || return 1
    [ -f "${root}/package/etc/rules/classification.config" ] || return 1
    [ -f "${root}/package/etc/rules/reference.config" ] || return 1
    [ -f "${root}/package/etc/rules/syno-custom-events.rules" ] || return 1
    [ -f "${root}/package/etc/suricata/threshold.config" ] || return 1
    [ -f "${root}/package/webapi/SYNO.TPS.lib" ] || return 1
    [ -f "${root}/spk/PACKAGE_ICON.PNG" ] || return 1
    [ -f "${root}/spk/PACKAGE_ICON_256.PNG" ] || return 1
}

download_official() {
    mkdir -p "$CACHE_DIR"
    local dest="${CACHE_DIR}/${OFFICIAL_SPK_NAME}"

    if [ -n "$OFFICIAL_SPK_OVERRIDE" ]; then
        [ -f "$OFFICIAL_SPK_OVERRIDE" ] || die "Official SPK not found: ${OFFICIAL_SPK_OVERRIDE}"
        info "Using ${OFFICIAL_SPK_OVERRIDE}"
        cp -f "$OFFICIAL_SPK_OVERRIDE" "$dest"
        return
    fi

    if [ -f "$dest" ]; then
        info "Official SPK already cached (${OFFICIAL_SPK_NAME})"
        return
    fi

    local urls=(
        "https://global.synologydownload.com/download/Package/spk/${OFFICIAL_PKG}/${OFFICIAL_VER}/${OFFICIAL_SPK_NAME}"
        "https://global.download.synology.com/download/Package/spk/${OFFICIAL_PKG}/${OFFICIAL_VER}/${OFFICIAL_SPK_NAME}"
        "https://archive.synology.com/download/Package/spk/${OFFICIAL_PKG}/${OFFICIAL_VER}/${OFFICIAL_SPK_NAME}"
        "https://archive.synology.com/download/Package/${OFFICIAL_PKG}/${OFFICIAL_VER}/${OFFICIAL_SPK_NAME}"
    )

    info "Downloading official ${OFFICIAL_SPK_NAME} (Synology copyright — cache only, not committed)"
    local ok=false url
    for url in "${urls[@]}"; do
        info "  ${url}"
        if curl -fSL --retry 3 -o "${dest}.part" "$url"; then
            # archive.synology.com sometimes 301s to an HTML index
            if file "${dest}.part" | grep -qi 'html'; then
                rm -f "${dest}.part"
                info "  got HTML, trying next mirror"
                continue
            fi
            mv "${dest}.part" "$dest"
            ok=true
            break
        fi
        rm -f "${dest}.part"
        info "  mirror failed, trying next"
    done
    if [ "$ok" != "true" ]; then
        die "Download failed. Place the official SPK at:
  ${dest}
or pass --official-spk /path/to/${OFFICIAL_SPK_NAME}"
    fi
}

extract_official() {
    if [ "$FORCE_EXTRACT" -eq 0 ] && official_complete "$OFFICIAL_DIR"; then
        info "Official inputs already extracted at ${OFFICIAL_DIR}"
        return
    fi

    local spk="${CACHE_DIR}/${OFFICIAL_SPK_NAME}"
    if [ ! -f "$spk" ] && official_complete "${SCRIPT_DIR}/unpacked"; then
        info "No cached SPK; using existing unpacked/ tree"
        mkdir -p "$OFFICIAL_DIR"
        rm -rf "$OFFICIAL_DIR"
        cp -a "${SCRIPT_DIR}/unpacked" "$OFFICIAL_DIR"
        return
    fi
    [ -f "$spk" ] || die "Missing ${spk}"

    assert_plain_spk "$spk"
    info "Extracting proprietary inputs from ${OFFICIAL_SPK_NAME}"

    local tmp="${SCRIPT_DIR}/build/official-tmp"
    rm -rf "$tmp"
    mkdir -p "$tmp/spk" "$tmp/pkg"
    export COPYFILE_DISABLE=1
    export COPY_EXTENDED_ATTRIBUTES_DISABLE=1

    tar xf "$spk" -C "$tmp/spk"
    [ -f "$tmp/spk/package.tgz" ] || die "package.tgz missing inside official SPK"
    tar xf "$tmp/spk/package.tgz" -C "$tmp/pkg"

    rm -rf "$OFFICIAL_DIR"
    mkdir -p \
        "${OFFICIAL_DIR}/spk" \
        "${OFFICIAL_DIR}/package/ui" \
        "${OFFICIAL_DIR}/package/etc/rules" \
        "${OFFICIAL_DIR}/package/etc/suricata" \
        "${OFFICIAL_DIR}/package/webapi"

    cp -a "$tmp/spk/PACKAGE_ICON.PNG" "${OFFICIAL_DIR}/spk/PACKAGE_ICON.PNG"
    cp -a "$tmp/spk/PACKAGE_ICON_256.PNG" "${OFFICIAL_DIR}/spk/PACKAGE_ICON_256.PNG"

    # ExtJS app, texts, official help, images — Synology copyright, cache only.
    cp -a "$tmp/pkg/ui/." "${OFFICIAL_DIR}/package/ui/"

    local f
    for f in emerging.rules.tar.gz signature.conf classification.config \
             reference.config syno-custom-events.rules version.txt; do
        if [ -f "$tmp/pkg/etc/rules/${f}" ]; then
            cp -a "$tmp/pkg/etc/rules/${f}" "${OFFICIAL_DIR}/package/etc/rules/${f}"
        fi
    done
    cp -a "$tmp/pkg/etc/suricata/threshold.config" \
        "${OFFICIAL_DIR}/package/etc/suricata/threshold.config"
    cp -a "$tmp/pkg/webapi/SYNO.TPS.lib" "${OFFICIAL_DIR}/package/webapi/SYNO.TPS.lib"

    rm -rf "$tmp"

    official_complete "$OFFICIAL_DIR" || die "Official extract incomplete under ${OFFICIAL_DIR}"
    info "Extracted UI / icons / rules / SYNO.TPS.lib (aarch64 binaries discarded)"
}

run_tests() {
    if [ "$SKIP_TESTS" -eq 1 ]; then
        return
    fi
    info "Community backend tests"
    python3 "${SRC_DIR}/python/test_compat.py"
}

build_engine() {
    if [ "$SKIP_ENGINE" -eq 1 ]; then
        [ -x "${SCRIPT_DIR}/build/suricata-8/out/tps-suricata/bin/suricata" ] \
            || die "--skip-engine set but ${SCRIPT_DIR}/build/suricata-8/out/tps-suricata/bin/suricata is missing"
        info "Skipping Suricata Docker build"
        return
    fi
    info "Building Suricata 8.0.6 (linux/amd64 via Docker)"
    "${SCRIPT_DIR}/build/suricata-8/build.sh"
    "${SCRIPT_DIR}/build/suricata-8/vendor-libs.sh"
}

pack_spk() {
    export TPS_OFFICIAL="$OFFICIAL_DIR"
    info "Packing community SPK"
    "${SCRIPT_DIR}/spk/pack-spk.sh"
}

main() {
    info "Threat Prevention DSM 7 PoC  (official source: ${OFFICIAL_SPK_NAME})"
    check_deps
    mkdir -p "$CACHE_DIR" "$OUT_DIR"
    download_official
    extract_official
    run_tests
    build_engine
    pack_spk
    info ""
    info "Done. SPK files in ${OUT_DIR}/:"
    ls -lh "${OUT_DIR}"/ThreatPrevention-x86_64-*.spk 2>/dev/null || ls -lh "${OUT_DIR}"/*.spk
    info "Do not commit build/cache/ or build/official/ (Synology copyright)."
}

main "$@"
