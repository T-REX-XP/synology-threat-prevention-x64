"""SYNO.TPS.* dispatch. Implementations stay in tpsweb; this file is the if-ladder."""


def _event_map(t, params, conn):
    return t.ok(t.official_map(conn, params.get("date_range")))


def _export_folder(t, params, conn):
    return t.ok({"export_folder": t.ensure_export_dir()})


def _sensor_get(t, params, conn):
    return t.ok(t.read_sensor())


def _sensor_vars(t, params, conn):
    return t.ok(t.sensor_vars())


def _gmaps_key(t, params, conn):
    return t.ok({"key": t.read_gmaps_key()})


def _nsm_device(t, params, conn):
    return t.ok(t.nsm_device_list())


def _systemdb(t, params, conn):
    return t.ok(t.systemdb_get())


def _usb_list(t, params, conn):
    return t.ok(t.usb_list())


# (api, method) → impl(t, params, conn). Unknown method on these APIs is 101.
EXACT = {
    ("SYNO.TPS.Event", "list"): lambda t, p, c: t.event_list(c, p),
    ("SYNO.TPS.Event", "get"): lambda t, p, c: t.event_get(c, p),
    ("SYNO.TPS.Event", "list_status"): lambda t, p, c: t.event_list_status(p),
    ("SYNO.TPS.Event.Offset", "get"): lambda t, p, c: t.event_offset(c, p),
    ("SYNO.TPS.Event.Statistic", "get"): lambda t, p, c: t.event_stat(c, p),
    ("SYNO.TPS.Event.Map", "list"): _event_map,
    ("SYNO.TPS.Event.ExportFolder", "get"): _export_folder,
    ("SYNO.TPS.Sensor", "get"): _sensor_get,
    ("SYNO.TPS.Sensor", "set"): lambda t, p, c: t.sensor_set(c, p),
    ("SYNO.TPS.Sensor.Variables", "get"): _sensor_vars,
    ("SYNO.TPS.Signature", "list"): lambda t, p, c: t.signature_classes(c),
    ("SYNO.TPS.Signature.Classification", "list"): lambda t, p, c: t.signature_classes(c),
    ("SYNO.TPS.Signature.Rule", "list"): lambda t, p, c: t.signature_rules(c, p),
    ("SYNO.TPS.Statistic.Trends", "get"): lambda t, p, c: t.trends(c, p),
    ("SYNO.TPS.Overview", "get"): lambda t, p, c: t.overview(c),
    ("SYNO.TPS.Settings.Map", "get"): _gmaps_key,
    ("SYNO.TPS.Compound", "request"): lambda t, p, c: t.handle_compound(p, c),
    ("SYNO.Core.Network.NSM.Device", "get"): _nsm_device,
    ("SYNO.Core.SystemDB", "get"): _systemdb,
    ("SYNO.Core.ExternalDevice.Storage.USB", "list"): _usb_list,
}

# api → impl(t, method, params, conn). Handler returns 102 for unknown methods.
BY_API = {
    "SYNO.TPS.Signature.Policy": lambda t, m, p, c: t.signature_policy(c, m, p),
    "SYNO.TPS.Settings.Storage": lambda t, m, p, c: t.settings_storage(c, m, p),
    "SYNO.TPS.Device": lambda t, m, p, c: t.devices(c, m, p),
    "SYNO.TPS.Statistic.Device": lambda t, m, p, c: t.stat_device(c, m, p),
    "SYNO.TPS.Notification": lambda t, m, p, c: t.notification(c, m, p),
    "SYNO.TPS.Notification.Filter": lambda t, m, p, c: t.notification_filter(c, m, p),
    "SYNO.TPS.Backup": lambda t, m, p, c: t.backup_api(c, m, p),
    "SYNO.TPS.Settings.Telegram": lambda t, m, p, c: t.settings_telegram(c, m, p),
    "SYNO.TPS.Settings.Mirror": lambda t, m, p, c: t.settings_mirror(m, p),
    "SYNO.TPS.Settings.Accel": lambda t, m, p, c: t.settings_accel(m, p),
    "SYNO.TPS.Settings.Feed": lambda t, m, p, c: t.settings_feed(c, m, p),
}

UPDATE_PREFIX = "SYNO.TPS.Settings.Update"


def dispatch(api, method, params, conn, impl):
    params = impl.coerce_params(params)
    fn = EXACT.get((api, method))
    if fn:
        return fn(impl, params, conn)
    fn = BY_API.get(api)
    if fn:
        return fn(impl, method, params, conn)
    if api.startswith(UPDATE_PREFIX):
        return impl.settings_update(conn, api, method, params)
    return impl.err(101)
