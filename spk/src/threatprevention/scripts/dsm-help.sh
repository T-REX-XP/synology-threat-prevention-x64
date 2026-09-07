#!/bin/sh
# Register / unregister this package in DSM Help (help.catalog + 3rdparty indexdb).
PKGDEST="${SYNOPKG_PKGDEST:-/var/packages/ThreatPrevention/target}"
ADD="/usr/syno/bin/pkgindexer_add"
DEL="/usr/syno/bin/pkgindexer_del"
HELP_CONF="${PKGDEST}/ui/helptoc.conf"
APP_CONF="${PKGDEST}/ui/index.conf"
HELP_DB="${PKGDEST}/indexdb/helpindexdb"
APP_DB="${PKGDEST}/indexdb/appindexdb"

ensure_db() {
	mkdir -p "${HELP_DB}" "${APP_DB}"
}

add() {
	ensure_db
	[ -x "${ADD}" ] || return 0
	[ -f "${HELP_CONF}" ] && "${ADD}" "${HELP_CONF}" "${HELP_DB}" >/dev/null 2>&1 || true
	[ -f "${APP_CONF}" ] && "${ADD}" "${APP_CONF}" "${APP_DB}" >/dev/null 2>&1 || true
}

del() {
	[ -x "${DEL}" ] || return 0
	[ -f "${HELP_CONF}" ] && "${DEL}" "${HELP_CONF}" "${HELP_DB}" >/dev/null 2>&1 || true
	[ -f "${APP_CONF}" ] && "${DEL}" "${APP_CONF}" "${APP_DB}" >/dev/null 2>&1 || true
}

case "$1" in
	add) add ;;
	del) del ;;
	*) exit 1 ;;
esac
exit 0
