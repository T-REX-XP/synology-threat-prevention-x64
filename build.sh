#!/usr/bin/env bash
# Build a DSM 7 x86_64 Threat Prevention PoC SPK from scratch.
#
# Community sources live in this repo. Official Synology ExtJS UI, icons,
# bootstrap ET tarball, and SYNO.TPS.lib are downloaded at build time from the
# public Package Center SPK and never stored in git.
#
# Unlike synology_codecs, this script does not decrypt SPKs or patch binaries.
# The SRM Threat Prevention package is a signed POSIX tar. Closed aarch64
# engines (.so / synosuricata) are discarded; Suricata 8 is built from source
# (or unpacked from a GitHub release artifact — see --from-release / install.sh).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=spk/common.sh
. "${SCRIPT_DIR}/spk/common.sh"

SKIP_ENGINE=0
SKIP_TESTS=0
FORCE_EXTRACT=0
FROM_RELEASE=0
RELEASE_TAG="latest"
ENGINE_TAR=""
GITHUB_REPO_ARG=""
OFFICIAL_SPK_OVERRIDE=""

usage() {
    cat <<EOF
Usage: $0 [options]

Build an unsigned DSM 7 x86_64 ThreatPrevention SPK.

  --from-release [TAG]  Use a prebuilt engine from GitHub Releases (no Docker)
  --engine-tar PATH     Unpack this ${ENGINE_ASSET} instead of compiling
  --repo owner/name     GitHub repo for --from-release (or TPS_GITHUB_REPO)
  --skip-engine         Reuse build/suricata-8/out
  --skip-tests          Do not run python/test_compat.py
  --official-spk PATH   Use this official .spk instead of downloading
  --force               Re-extract official files even if build/official exists
  -h, --help            Show this help

Default (developer): download ${OFFICIAL_SPK_NAME}, compile Suricata 8 via
Docker, pack artifact/*.spk.

NAS (no compile): ./install.sh
EOF
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-engine) SKIP_ENGINE=1; shift ;;
        --skip-tests) SKIP_TESTS=1; shift ;;
        --force) FORCE_EXTRACT=1; export FORCE_EXTRACT; shift ;;
        --from-release)
            FROM_RELEASE=1
            if [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then
                RELEASE_TAG="$2"
                shift 2
            else
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

check_deps() {
    local missing=()
    for cmd in tar curl python3; do
        command -v "$cmd" >/dev/null || missing+=("$cmd")
    done
    local need_docker=1
    if [ "$SKIP_ENGINE" -eq 1 ] || [ "$FROM_RELEASE" -eq 1 ] || [ -n "$ENGINE_TAR" ]; then
        need_docker=0
    fi
    if [ "$need_docker" -eq 1 ]; then
        command -v docker >/dev/null || missing+=("docker")
    fi
    if [ ${#missing[@]} -gt 0 ]; then
        die "Missing required tools: ${missing[*]}"
    fi
    [ -d "$SRC_DIR" ] || die "Missing community sources at ${SRC_DIR}"
}

run_tests() {
    if [ "$SKIP_TESTS" -eq 1 ]; then
        return
    fi
    info "Community backend tests"
    python3 "${SRC_DIR}/python/test_compat.py"
}

ensure_engine() {
    if [ -n "$ENGINE_TAR" ]; then
        unpack_engine_tar "$ENGINE_TAR"
        return
    fi
    if [ "$FROM_RELEASE" -eq 1 ]; then
        local repo="${GITHUB_REPO_ARG}"
        if [ -z "$repo" ]; then
            repo="$(detect_github_repo)" || die "Pass --repo owner/name (or set TPS_GITHUB_REPO)"
        fi
        local tarpath
        tarpath="$(download_engine_release "$repo" "$RELEASE_TAG")"
        unpack_engine_tar "$tarpath"
        return
    fi
    if [ "$SKIP_ENGINE" -eq 1 ]; then
        engine_ready || die "--skip-engine set but ${ENGINE_OUT}/tps-suricata/bin/suricata is missing"
        info "Skipping Suricata Docker build"
        return
    fi
    info "Building Suricata ${SURICATA_VERSION} (linux/amd64 via Docker)"
    bash "${SCRIPT_DIR}/build/suricata-8/build.sh"
}

pack_spk() {
    export TPS_OFFICIAL="$OFFICIAL_DIR"
    info "Packing community SPK"
    bash "${SCRIPT_DIR}/spk/pack-spk.sh"
}

main() {
    info "Threat Prevention DSM 7 PoC  (official source: ${OFFICIAL_SPK_NAME})"
    check_deps
    mkdir -p "$CACHE_DIR" "$OUT_DIR"
    download_official
    extract_official
    run_tests
    ensure_engine
    pack_spk
    info ""
    info "Done. SPK files in ${OUT_DIR}/:"
    ls -lh "$(spk_path)" 2>/dev/null || ls -lh "${OUT_DIR}"/*.spk
    info "Do not commit build/cache/ or build/official/ (Synology copyright)."
}

main "$@"
