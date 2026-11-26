#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
unset TPS_PKG_VERSION
export GITHUB_REF_NAME=v0.3.1 TPS_BRANCH=main
. "${SCRIPT_DIR}/spk/pkg-version.sh"
[[ "$PKG_VERSION" == "$(sed -n 's/^version="\([^"]*\)"$/\1/p' "${SCRIPT_DIR}/spk/src/threatprevention/INFO")" ]]

TPS_PKG_VERSION=8.0.8-0077
. "${SCRIPT_DIR}/spk/pkg-version.sh"
[[ "$PKG_VERSION" == 8.0.8-0077 ]]

for invalid in main v0.3.1 8.0.8 2147483648.0-0001; do
    if (TPS_PKG_VERSION="$invalid"; . "${SCRIPT_DIR}/spk/pkg-version.sh") 2>/dev/null; then
        printf 'Unexpectedly accepted package version %s\n' "$invalid" >&2
        exit 1
    fi
done
echo "DSM package version tests passed"
