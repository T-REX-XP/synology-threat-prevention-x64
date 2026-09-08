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
# DSM python3 has no PyYAML. The SPK vendors a pure-Python copy.
export PYTHONPATH="${PKGDEST}/lib/tps:${PKGDEST}/lib/python:${PKGDEST}/lib/suricata/python${PYTHONPATH:+:${PYTHONPATH}}"

PYJSON=""
for c in /usr/bin/python3 /usr/local/bin/python3 python3; do
	if command -v "${c}" >/dev/null 2>&1 || [ -x "${c}" ]; then
		PYJSON="${c}"
		break
	fi
done

if [ -z "${PYJSON}" ]; then
	echo "python3 missing; cannot read rule-sources.json" >&2
	exit 2
fi

KIND="et-open"
if [ "${SOURCE}" = "et-pro" ]; then
	if [ -z "${CODE}" ]; then
		echo "ET Pro code missing" >&2
		exit 2
	fi
	KIND="et-pro"
fi

ET_URL="$("${PYJSON}" - "${KIND}" "${CODE}" <<'PY'
import sys
from rule_sources import source_urls
urls = source_urls(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")
if not urls:
    sys.exit(1)
print(urls[0])
PY
)" || {
	echo "${KIND} url missing in rule-sources.json" >&2
	exit 2
}

# Ignore suricata-update's built-in ET Open URL; JSON is the source of truth.
"${BIN}" disable-source et/open \
	--data-dir "${SU_DATA}" >>"${LOG}" 2>&1 || true
rm -f "${SU_DATA}/sources/et-pro.yaml" "${SU_DATA}/sources/et-open.yaml"
printf 'url: %s\n' "${ET_URL}" > "${SU_DATA}/sources/${KIND}.yaml"

# Additive custom feeds from Settings → Rule feeds (etc/feeds.json).
if [ -r "${PKGETC}/feeds.json" ]; then
	if [ -n "${PYJSON}" ]; then
		"${PYJSON}" - "${PKGETC}/feeds.json" "${SU_DATA}/sources" >>"${LOG}" 2>&1 <<'PY'
import json, os, re, sys
path, dest = sys.argv[1], sys.argv[2]
os.makedirs(dest, exist_ok=True)
try:
    payload = json.load(open(path, encoding="utf-8"))
except Exception:
    payload = {}
wanted = set()
safe = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
for item in payload.get("feeds") or []:
    name = str(item.get("name") or "")
    url = str(item.get("url") or "")
    if not item.get("enabled", True) or not safe.match(name) or not url.startswith(("https://", "http://")):
        continue
    wanted.add(name)
    with open(os.path.join(dest, "custom-%s.yaml" % name), "w", encoding="utf-8") as fh:
        fh.write("url: %s\n" % url)
for fn in os.listdir(dest):
    if fn.startswith("custom-") and fn.endswith(".yaml"):
        name = fn[7:-5]
        if name not in wanted:
            try:
                os.remove(os.path.join(dest, fn))
            except OSError:
                pass
PY
	fi
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
