# Sets the numeric DSM package version from INFO or TPS_PKG_VERSION.
# SCRIPT_DIR or ROOT must be the repo root.
# shellcheck shell=bash

_tps_valid_pkg_ver() {
    local part
    local -a parts
    [[ "$1" =~ ^([0-9]{1,10}\.){1,2}[0-9]{1,10}-[0-9]{1,10}$ ]] || return 1
    IFS='.-' read -r -a parts <<< "$1"
    for part in "${parts[@]}"; do
        (( 10#$part <= 2147483647 )) || return 1
    done
}

PKG_VERSION="${TPS_PKG_VERSION:-}"
if [ -z "$PKG_VERSION" ]; then
    _tps_info="${SCRIPT_DIR:-${ROOT:-.}}/spk/src/threatprevention/INFO"
    PKG_VERSION="$(sed -n 's/^version="\([^"]*\)"$/\1/p' "$_tps_info")"
fi
if ! _tps_valid_pkg_ver "$PKG_VERSION"; then
    printf 'ERROR: DSM package version "%s" is invalid. Use a numeric version such as 8.0.8-0068.\n' "$PKG_VERSION" >&2
    return 1
fi
