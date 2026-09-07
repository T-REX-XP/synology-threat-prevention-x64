#!/bin/sh
# Replace the 2021 ET-for-Suricata-5 tarball with current ET Open (or ET Pro).
# Do not try to "convert" the old rules; syntax (sticky buffers, xbits) differs.
set -e
PKGDEST="${SYNOPKG_PKGDEST:-/var/packages/ThreatPrevention/target}"
PKGVAR="/var/packages/ThreatPrevention/var"
PKGETC="/var/packages/ThreatPrevention/etc"
BIN="${PKGDEST}/bin/suricata-update"
OUT="${PKGVAR}/rules"
LOG="${PKGVAR}/log/suricata-update.log"
SU_DATA="${PKGVAR}/suricata-update"
SOURCE="et-open"
CODE=""

if [ -r "${PKGETC}/update-source" ]; then
	SOURCE="$(tr -d '\r\n' < "${PKGETC}/update-source")"
fi
if [ -r "${PKGETC}/etpro.code" ]; then
	CODE="$(tr -d '\r\n' < "${PKGETC}/etpro.code")"
fi

if [ ! -x "${BIN}" ]; then
	echo "suricata-update missing" >&2
	exit 1
fi

mkdir -p "${OUT}" "${SU_DATA}/sources" "${PKGVAR}/log"
export PYTHONPATH="${PKGDEST}/lib/suricata/python${PYTHONPATH:+:${PYTHONPATH}}"

if [ "${SOURCE}" = "et-pro" ]; then
	if [ -z "${CODE}" ]; then
		echo "ET Pro code missing" >&2
		exit 2
	fi
	"${BIN}" disable-source et/open \
		--data-dir "${SU_DATA}" >>"${LOG}" 2>&1 || true
	# Non-interactive: drop a source file instead of the enable-source prompt.
	cat > "${SU_DATA}/sources/et-pro.yaml" <<EOF
url: https://rules.emergingthreatspro.com/${CODE}/suricata-8.0/etpro.rules.tar.gz
EOF
else
	rm -f "${SU_DATA}/sources/et-pro.yaml"
	"${BIN}" enable-source et/open \
		--data-dir "${SU_DATA}" >>"${LOG}" 2>&1 || true
fi

"${BIN}" update-sources \
	--suricata "${PKGDEST}/bin/suricata" \
	--data-dir "${SU_DATA}" \
	>>"${LOG}" 2>&1 || true

"${BIN}" \
	--suricata "${PKGDEST}/bin/suricata" \
	--suricata-conf "${PKGDEST}/etc/suricata/suricata.yaml" \
	--data-dir "${SU_DATA}" \
	--output "${OUT}" \
	--no-test \
	>>"${LOG}" 2>&1

if [ ! -s "${OUT}/suricata.rules" ]; then
	echo "update produced no suricata.rules (see ${LOG})" >&2
	exit 1
fi
echo "Wrote ${OUT}/suricata.rules"
cp -f "${OUT}/suricata.rules" "${OUT}/catalog.rules"
: > "${OUT}/.from-suricata-update"
echo "Restart the package to load the new rules: synopkg restart ThreatPrevention"
