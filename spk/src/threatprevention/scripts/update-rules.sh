#!/bin/sh
# Replace the 2021 ET-for-Suricata-5 tarball with current ET Open for Suricata 8.
# Do not try to "convert" the old rules; syntax (sticky buffers, xbits) differs.
set -e
PKGDEST="${SYNOPKG_PKGDEST:-/var/packages/ThreatPrevention/target}"
PKGVAR="/var/packages/ThreatPrevention/var"
BIN="${PKGDEST}/bin/suricata-update"
OUT="${PKGVAR}/rules"
LOG="${PKGVAR}/log/suricata-update.log"

if [ ! -x "${BIN}" ]; then
	echo "suricata-update missing" >&2
	exit 1
fi

mkdir -p "${OUT}" "${PKGVAR}/suricata-update" "${PKGVAR}/log"
export PYTHONPATH="${PKGDEST}/lib/suricata/python${PYTHONPATH:+:${PYTHONPATH}}"

"${BIN}" update-sources \
	--suricata "${PKGDEST}/bin/suricata" \
	--data-dir "${PKGVAR}/suricata-update" \
	>>"${LOG}" 2>&1 || true

"${BIN}" \
	--suricata "${PKGDEST}/bin/suricata" \
	--suricata-conf "${PKGDEST}/etc/suricata/suricata.yaml" \
	--data-dir "${PKGVAR}/suricata-update" \
	--output "${OUT}" \
	--no-test \
	>>"${LOG}" 2>&1

if [ ! -s "${OUT}/suricata.rules" ]; then
	echo "update produced no suricata.rules (see ${LOG})" >&2
	exit 1
fi
echo "Wrote ${OUT}/suricata.rules"
: > "${OUT}/.from-suricata-update"
echo "Restart the package to load the new rules: synopkg restart ThreatPrevention"
