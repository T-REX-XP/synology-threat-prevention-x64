#!/usr/bin/env bash
# Prepare and install Threat Prevention on a DSM 7 x86_64 NAS.
#
# Task Scheduler as root (Control Panel → User-defined script, User: root):
#   curl -fsSL https://raw.githubusercontent.com/T-REX-XP/synology-threat-prevention-x64/main/install.sh | bash
# SSH (not already root):
#   curl -fsSL https://raw.githubusercontent.com/T-REX-XP/synology-threat-prevention-x64/main/install.sh | sudo bash
# Optional pin of the engine GitHub Release:
#   … | bash -s -- --tag v0.2.0
#
# Does not compile Suricata. Fetches a prebuilt engine from GitHub Releases,
# downloads the official SRM UI SPK, packs a community SPK, then synopkg
# install + setcap.
set -euo pipefail

DEFAULT_REPO="${TPS_GITHUB_REPO:-T-REX-XP/synology-threat-prevention-x64}"
DEFAULT_BRANCH="${TPS_BRANCH:-main}"

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*" >&2; }

ORIG_ARGS=("$@")
SKIP_INSTALL=0
SKIP_SETCAP=0
RELEASE_TAG="latest"
ENGINE_TAR=""
GITHUB_REPO_ARG=""
OFFICIAL_SPK_OVERRIDE=""
FORCE_EXTRACT=0
FORCE_ENGINE=0

usage() {
    cat <<EOF
Usage: $0 [options]

On a DSM 7 Intel/AMD NAS: fetch the prebuilt Suricata engine, assemble the
SPK (official UI is downloaded here, not from GitHub), install, setcap.

  # Task Scheduler as root:
  curl -fsSL https://raw.githubusercontent.com/${DEFAULT_REPO}/main/install.sh | bash
  # SSH:
  curl -fsSL https://raw.githubusercontent.com/${DEFAULT_REPO}/main/install.sh | sudo bash

  --repo owner/name       GitHub repo (default: ${DEFAULT_REPO})
  --tag [TAG]             Engine GitHub Release (optional; default: latest).
                          Installer sources always come from ${DEFAULT_BRANCH}.
  --engine-tar PATH       Use a local engine tarball
  --official-spk PATH     Use a local official Threat Prevention .spk
  --skip-install          Pack only (do not synopkg)
  --no-setcap             Install but skip setcap
  --force                 Re-extract official UI and re-download engine
  -h, --help

Requires: curl, tar, python3. Docker is not required.
Package Center → Trust Level must allow unsigned packages.
EOF
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-install) SKIP_INSTALL=1; shift ;;
        --no-setcap) SKIP_SETCAP=1; shift ;;
        --force) FORCE_EXTRACT=1; FORCE_ENGINE=1; export FORCE_EXTRACT FORCE_ENGINE; shift ;;
        --tag)
            if [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then
                RELEASE_TAG="$2"
                shift 2
            else
                RELEASE_TAG="latest"
                shift
            fi
            ;;
        --engine-tar)
            [ $# -ge 2 ] || usage
            ENGINE_TAR="$2"
            shift 2
            ;;
        --repo)
            [ $# -ge 2 ] || usage
            GITHUB_REPO_ARG="$2"
            shift 2
            ;;
        --official-spk)
            [ $# -ge 2 ] || usage
            OFFICIAL_SPK_OVERRIDE="$2"
            export OFFICIAL_SPK_OVERRIDE
            shift 2
            ;;
        -h|--help) usage ;;
        *) usage ;;
    esac
done

[ -n "$RELEASE_TAG" ] || RELEASE_TAG="latest"

repo_root() {
    if [ -n "${TPS_ROOT:-}" ] && [ -f "${TPS_ROOT}/VERSION" ] && [ -d "${TPS_ROOT}/spk/src/threatprevention" ]; then
        echo "${TPS_ROOT}"
        return 0
    fi
    local src="${BASH_SOURCE[0]:-}"
    if [ -n "$src" ] && [ -f "$src" ]; then
        local d
        d="$(cd "$(dirname "$src")" && pwd)"
        if [ -f "$d/VERSION" ] && [ -d "$d/spk/src/threatprevention" ]; then
            echo "$d"
            return 0
        fi
    fi
    return 1
}

bootstrap_sources() {
    local repo="${GITHUB_REPO_ARG:-$DEFAULT_REPO}"
    local work url
    work="$(mktemp -d "${TMPDIR:-/tmp}/tps-install.XXXXXX")"
    # Always fetch installer sources from the branch this script lives on.
    # --tag only pins the engine Release asset; pinning sources to an old tag
    # would re-exec a broken unpacker (BusyBox tar -C) forever.
    url="https://github.com/${repo}/archive/refs/heads/${DEFAULT_BRANCH}.tar.gz"
    info "Downloading ${repo} @ ${DEFAULT_BRANCH}"
    info "  ${url}"
    mkdir -p "$work"
    # Pipe to tar with -C before the archive (stdin). Do not use tar -xzf FILE -C
    # DEST: DSM BusyBox ignores -C after -f.
    curl -fsSL --retry 3 "$url" | tar -xz -C "$work" --strip-components=1
    [ -f "$work/install.sh" ] && [ -f "$work/VERSION" ] || die "GitHub archive is missing install.sh / VERSION"
    # GitHub tarballs / BusyBox tar often drop +x. Always run scripts with bash.
    chmod +x "$work/install.sh" "$work/build.sh" "$work/spk/"*.sh 2>/dev/null || true
    export TPS_GITHUB_REPO="$repo"
    info "Re-running installer from ${work}"
    exec bash "$work/install.sh" "${ORIG_ARGS[@]}"
}

if ! SCRIPT_DIR="$(repo_root)"; then
    command -v curl >/dev/null || die "Missing curl"
    command -v tar >/dev/null || die "Missing tar"
    bootstrap_sources
fi

export TPS_GITHUB_REPO="${GITHUB_REPO_ARG:-${TPS_GITHUB_REPO:-$DEFAULT_REPO}}"
# shellcheck source=spk/common.sh
. "${SCRIPT_DIR}/spk/common.sh"

check_nas_arch() {
    local m
    m="$(uname -m)"
    case "$m" in
        x86_64|amd64) return 0 ;;
    esac
    if command -v synopkg >/dev/null 2>&1; then
        die "This package is x86_64 only (this NAS is ${m})"
    fi
    return 0
}

ensure_prebuilt_engine() {
    if engine_ready && [ -z "$ENGINE_TAR" ] && [ "$FORCE_ENGINE" -eq 0 ]; then
        info "Using existing ${ENGINE_OUT}/tps-suricata"
        return
    fi
    if [ -n "$ENGINE_TAR" ]; then
        unpack_engine_tar "$ENGINE_TAR"
        return
    fi
    local repo="${GITHUB_REPO_ARG:-${TPS_GITHUB_REPO}}"
    [ -n "$repo" ] || die "Pass --repo owner/name (GitHub repo that publishes ${ENGINE_ASSET})"
    local tarpath
    tarpath="$(download_engine_release "$repo" "$RELEASE_TAG")"
    unpack_engine_tar "$tarpath"
}

install_spk() {
    local spk
    spk="$(spk_path)"
    [ -f "$spk" ] || die "SPK not produced: ${spk}"

    if [ "$SKIP_INSTALL" -eq 1 ]; then
        info "Packed ${spk} (--skip-install)"
        return
    fi

    if ! command -v synopkg >/dev/null 2>&1 && [ ! -x /usr/syno/bin/synopkg ]; then
        info "Not a DSM host. Copy and install on the NAS:"
        info "  scp -O ${spk} admin@nas:/tmp/"
        info "  ssh admin@nas sudo synopkg install /tmp/$(basename "$spk")"
        return
    fi

    local synopkg
    synopkg="$(command -v synopkg || echo /usr/syno/bin/synopkg)"
    info "Installing $(basename "$spk") (unsigned — Trust Level must allow it)"
    as_root "$synopkg" install "$spk"

    if [ "$SKIP_SETCAP" -eq 0 ]; then
        local bin="/var/packages/ThreatPrevention/target/bin/suricata"
        info "setcap on ${bin}"
        as_root /usr/bin/setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep "$bin"
        as_root "$synopkg" restart ThreatPrevention || as_root "$synopkg" start ThreatPrevention
        info "getcap: $(as_root /usr/bin/getcap "$bin" 2>/dev/null || true)"
    fi

    info "Log out of DSM and back in so the Start Menu loads synoips.js?v=$(pkg_ver)"
}

main() {
    info "NAS install (no compile)  package $(pkg_ver)"
    check_nas_arch
    for cmd in tar curl python3; do
        command -v "$cmd" >/dev/null || die "Missing ${cmd}"
    done
    [ -d "$SRC_DIR" ] || die "Missing community sources at ${SRC_DIR}"
    mkdir -p "$CACHE_DIR" "$OUT_DIR"
    ensure_prebuilt_engine
    local pack_args=(--skip-engine --skip-tests)
    if [ "$FORCE_EXTRACT" -eq 1 ]; then
        pack_args+=(--force)
    fi
    if [ -n "${OFFICIAL_SPK_OVERRIDE}" ]; then
        pack_args+=(--official-spk "$OFFICIAL_SPK_OVERRIDE")
    fi
    bash "${SCRIPT_DIR}/build.sh" "${pack_args[@]}"
    install_spk
}

main
