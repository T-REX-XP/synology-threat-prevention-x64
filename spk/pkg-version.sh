# Sets PKG_VERSION from TPS_PKG_VERSION, GitHub ref, git tag, or git branch.
# SCRIPT_DIR or ROOT must be the repo root. Safe without .git (GitHub tarball).
# shellcheck shell=bash

_tps_sanitize_pkg_ver() {
    echo "$1" | tr '/' '-' | tr -cd 'A-Za-z0-9._-'
}

_tps_git_root="${SCRIPT_DIR:-${ROOT:-.}}"

if [ -n "${TPS_PKG_VERSION:-}" ]; then
    PKG_VERSION="$(_tps_sanitize_pkg_ver "$TPS_PKG_VERSION")"
elif [ -n "${GITHUB_REF_NAME:-}" ]; then
    PKG_VERSION="$(_tps_sanitize_pkg_ver "$GITHUB_REF_NAME")"
else
    PKG_VERSION=""
    if git -C "${_tps_git_root}" rev-parse --git-dir >/dev/null 2>&1; then
        PKG_VERSION="$(git -C "${_tps_git_root}" branch --show-current 2>/dev/null || true)"
        if [ -z "$PKG_VERSION" ] || [ "$PKG_VERSION" = "HEAD" ]; then
            PKG_VERSION="$(git -C "${_tps_git_root}" describe --tags --exact-match 2>/dev/null || true)"
        fi
        if [ -z "$PKG_VERSION" ]; then
            PKG_VERSION="$(git -C "${_tps_git_root}" describe --always --tags 2>/dev/null || true)"
        fi
    fi
    PKG_VERSION="$(_tps_sanitize_pkg_ver "${PKG_VERSION:-${TPS_BRANCH:-main}}")"
fi
[ -n "$PKG_VERSION" ] || PKG_VERSION="main"
