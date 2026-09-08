#!/bin/sh
# Root-only fallback when nginx-static-config did not inject the tpsweb proxy.
# Usage: sudo /var/packages/ThreatPrevention/scripts/install-nginx-api.sh
SRC="/var/packages/ThreatPrevention/target/etc/nginx/dsm-tpsweb.conf"
DIR="/usr/syno/share/nginx/conf.d"
if [ ! -f "${SRC}" ]; then
	echo "missing ${SRC}" >&2
	exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
	echo "run as root" >&2
	exit 1
fi
if [ ! -d "${DIR}" ]; then
	echo "missing ${DIR}" >&2
	exit 1
fi

ok_nginx() {
	if command -v nginx >/dev/null 2>&1; then
		nginx -t >/dev/null 2>&1
	else
		return 0
	fi
}

cp -f "${SRC}" "${DIR}/www.ThreatPrevention-tpsapi.conf"
if ! ok_nginx; then
	rm -f "${DIR}/www.ThreatPrevention-tpsapi.conf"
	echo "www snippet failed nginx -t" >&2
	exit 1
fi
echo "installed ${DIR}/www.ThreatPrevention-tpsapi.conf"

cp -f "${SRC}" "${DIR}/dsm.ThreatPrevention-tpsapi.conf"
if ! ok_nginx; then
	rm -f "${DIR}/dsm.ThreatPrevention-tpsapi.conf"
	echo "dsm snippet skipped (duplicate location in this server)"
else
	echo "installed ${DIR}/dsm.ThreatPrevention-tpsapi.conf"
fi

if [ -x /usr/syno/bin/synosystemctl ]; then
	/usr/syno/bin/synosystemctl reload nginx.service 2>/dev/null \
		|| /usr/syno/bin/synosystemctl restart nginx.service 2>/dev/null \
		|| nginx -s reload
elif command -v synoservice >/dev/null 2>&1; then
	synoservice --reload nginx.service 2>/dev/null || synoservice --restart nginx
else
	nginx -s reload
fi
echo "tps-api proxy ready"
