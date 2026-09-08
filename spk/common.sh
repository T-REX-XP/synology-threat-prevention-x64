# Shared helpers for build.sh and install.sh. SCRIPT_DIR must be the repo root.
# shellcheck shell=bash

OFFICIAL_PKG="ThreatPrevention"
OFFICIAL_VER="1.3.3-0926"
OFFICIAL_ARCH="cypress"
OFFICIAL_SPK_NAME="${OFFICIAL_PKG}-${OFFICIAL_ARCH}-${OFFICIAL_VER}.spk"

SURICATA_VER="8.0.6"
ENGINE_ASSET="suricata-${SURICATA_VER}-linux-amd64.tar.gz"

CACHE_DIR="${SCRIPT_DIR}/build/cache"
OFFICIAL_DIR="${SCRIPT_DIR}/build/official"
ENGINE_OUT="${SCRIPT_DIR}/build/suricata-8/out"
OUT_DIR="${SCRIPT_DIR}/artifact"
SRC_DIR="${SCRIPT_DIR}/spk/src/threatprevention"

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*" >&2; }

pkg_ver() {
    grep '^version=' "${SRC_DIR}/INFO" | cut -d= -f2 | tr -d '"'
}

spk_path() {
    echo "${OUT_DIR}/ThreatPrevention-x86_64-$(pkg_ver).spk"
}

detect_github_repo() {
    if [ -n "${TPS_GITHUB_REPO:-}" ]; then
        echo "${TPS_GITHUB_REPO}"
        return
    fi
    local url
    url="$(git -C "${SCRIPT_DIR}" remote get-url origin 2>/dev/null || true)"
    [ -n "$url" ] || return 1
    echo "$url" | sed -E 's#(git@github.com:|https://github.com/)##; s#\.git$##'
}

engine_ready() {
    [ -x "${ENGINE_OUT}/tps-suricata/bin/suricata" ]
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

# Reject Synology encrypted SPKs (keytype 3).
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

is_html_file() {
    python3 - "$1" <<'PY'
import sys
data = open(sys.argv[1], "rb").read(256).lstrip().lower()
sys.exit(0 if data.startswith(b"<!doctype") or data.startswith(b"<html") else 1)
PY
}

download_official() {
    mkdir -p "$CACHE_DIR"
    local dest="${CACHE_DIR}/${OFFICIAL_SPK_NAME}"

    if [ -n "${OFFICIAL_SPK_OVERRIDE:-}" ]; then
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
            if is_html_file "${dest}.part"; then
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
    if [ "${FORCE_EXTRACT:-0}" -eq 0 ] && official_complete "$OFFICIAL_DIR"; then
        info "Official inputs already extracted at ${OFFICIAL_DIR}"
        return
    fi

    local spk="${CACHE_DIR}/${OFFICIAL_SPK_NAME}"
    if [ ! -f "$spk" ] && official_complete "${SCRIPT_DIR}/unpacked"; then
        info "No cached SPK; using existing unpacked/ tree"
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

unpack_engine_tar() {
    local tarpath="$1"
    [ -f "$tarpath" ] || die "Engine tarball not found: ${tarpath}"
    mkdir -p "$ENGINE_OUT"
    rm -rf "${ENGINE_OUT}/tps-suricata"
    info "Unpacking ${tarpath}"
    tar -xzf "$tarpath" -C "$ENGINE_OUT"
    engine_ready || die "Engine tarball did not contain tps-suricata/bin/suricata"
}

github_engine_url() {
    local repo="$1" tag="${2:-latest}"
    if [ "$tag" = "latest" ]; then
        echo "https://github.com/${repo}/releases/latest/download/${ENGINE_ASSET}"
    else
        echo "https://github.com/${repo}/releases/download/${tag}/${ENGINE_ASSET}"
    fi
}

download_engine_release() {
    local repo="$1" tag="${2:-latest}"
    mkdir -p "$CACHE_DIR"
    local dest="${CACHE_DIR}/${ENGINE_ASSET}"
    if [ -f "$dest" ] && [ "${FORCE_ENGINE:-0}" -eq 0 ]; then
        info "Engine tarball already cached (${ENGINE_ASSET})"
        echo "$dest"
        return
    fi

    local url
    url="$(github_engine_url "$repo" "$tag")"
    info "Downloading prebuilt engine from ${url}"
    local curl_auth=()
    if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
        curl_auth=(-H "Authorization: Bearer ${GH_TOKEN:-${GITHUB_TOKEN}}")
    fi
    curl -fSL --retry 3 "${curl_auth[@]}" -o "${dest}.part" "$url" \
        || die "Failed to download ${ENGINE_ASSET} from ${url}
Set TPS_GITHUB_REPO=owner/name, or pass --engine-tar /path/to/${ENGINE_ASSET}
To compile instead: ./build.sh"
    if is_html_file "${dest}.part"; then
        rm -f "${dest}.part"
        die "GitHub returned HTML (release/asset missing?). Tag a release that includes ${ENGINE_ASSET}."
    fi
    mv "${dest}.part" "$dest"

    local sum_url="${url}.sha256"
    if curl -fsSL "${curl_auth[@]}" -o "${dest}.sha256" "$sum_url"; then
        info "Verifying SHA-256"
        python3 - "$dest" "${dest}.sha256" <<'PY'
import hashlib, sys
blob, sumfile = sys.argv[1], sys.argv[2]
want = open(sumfile, encoding="utf-8").read().split()[0].strip().lower()
got = hashlib.sha256(open(blob, "rb").read()).hexdigest()
if got != want:
    sys.exit(f"SHA-256 mismatch: expected {want}, got {got}")
print("SHA-256 ok", file=sys.stderr)
PY
    else
        rm -f "${dest}.sha256"
        info "No .sha256 asset; skipping checksum"
    fi
    echo "$dest"
}

as_root() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}
