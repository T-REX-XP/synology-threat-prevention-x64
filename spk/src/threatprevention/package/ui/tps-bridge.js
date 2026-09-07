/* Research PoC compatibility layer.
   Official synoips.js talks only to DSM sendWebAPI / SYNO.API.Store / pollReg
   (entry.cgi → SYNO.TPS.*.so). Those .so files are aarch64 and cannot load on
   x86_64 DSM. This original hook sends SYNO.TPS.* to tpsweb on :19557, which
   implements the official envelopes on top of vanilla Suricata 8. */
Ext.namespace("SYNO.SDS.TPS");

SYNO.SDS.TPS.Bridge = {
	base: function () {
		var host = window.location.hostname || "127.0.0.1";
		return "http://" + host + ":19557/";
	},
	apis: [
		"SYNO.TPS.Backup", "SYNO.TPS.Device", "SYNO.TPS.Event", "SYNO.TPS.Event.ExportFolder",
		"SYNO.TPS.Event.Map", "SYNO.TPS.Event.Offset", "SYNO.TPS.Event.Statistic",
		"SYNO.TPS.Notification", "SYNO.TPS.Notification.Filter", "SYNO.TPS.Sensor",
		"SYNO.TPS.Sensor.Variables", "SYNO.TPS.Settings.Storage", "SYNO.TPS.Settings.Update",
		"SYNO.TPS.Settings.Update.Schedule", "SYNO.TPS.Settings.Update.Source",
		"SYNO.TPS.Signature", "SYNO.TPS.Signature.Classification", "SYNO.TPS.Signature.Policy",
		"SYNO.TPS.Signature.Rule", "SYNO.TPS.Statistic.Device", "SYNO.TPS.Statistic.Trends"
	],
	encodeParams: function (params) {
		var out = {}, k, v;
		params = params || {};
		for (k in params) {
			if (!params.hasOwnProperty(k)) { continue; }
			v = params[k];
			if (v !== null && typeof v === "object") {
				out[k] = Ext.encode(v);
			} else {
				out[k] = v;
			}
		}
		return out;
	},
	call: function (api, method, version, params, cb, scope) {
		var q = Ext.apply({ api: api, method: method, version: version || 1 }, this.encodeParams(params));
		Ext.Ajax.request({
			url: this.base(),
			method: "POST",
			params: q,
			_tpsDirect: true,
			success: function (resp) {
				var j = {};
				try { j = Ext.decode(resp.responseText); } catch (e) { j = { success: false }; }
				if (cb) {
					cb.call(scope || window, !!j.success, j.data || {}, j, q);
				}
			},
			failure: function (resp) {
				var err = { success: false, error: { code: 500 } };
				if (resp && resp.status === 0) {
					err.error = { code: 500, isTimeout: false, message: "tpsweb unreachable (use HTTP DSM :5000, not HTTPS mixed content)" };
				}
				if (cb) { cb.call(scope || window, false, err.error || {}, err, q); }
			}
		});
	},
	isTps: function (api) {
		return api && String(api).indexOf("SYNO.TPS.") === 0;
	},
	dispatch: function (opts, fallback, ctx) {
		if (!opts) { return fallback.call(ctx); }
		if (opts.compound && opts.compound.params) {
			return this.compound(opts);
		}
		var api = opts.api || (opts.webapi && opts.webapi.api);
		var method = opts.method || (opts.webapi && opts.webapi.method);
		var version = opts.version || (opts.webapi && opts.webapi.version) || 1;
		var params = opts.params || (opts.webapi && opts.webapi.params) || {};
		if (!this.isTps(api)) {
			return fallback.call(ctx);
		}
		var cb = opts.callback || opts.status_callback;
		var scope = opts.scope || ctx;
		this.call(api, method, version, params, cb, scope);
		return true;
	},
	compound: function (opts) {
		var me = this;
		var items = opts.compound.params || [];
		var out = [];
		var left = items.length;
		var failed = false;
		if (!left) {
			if (opts.callback) { opts.callback.call(opts.scope || window, true, { result: [], has_fail: false }); }
			return true;
		}
		Ext.each(items, function (item, idx) {
			me.call(item.api, item.method, item.version || 1, item.params || {}, function (ok, data, raw) {
				out[idx] = { api: item.api, method: item.method, success: ok, data: data };
				if (!ok) {
					failed = true;
					out[idx].error = (raw && raw.error) || { code: 500 };
				}
				left -= 1;
				if (!left && opts.callback) {
					opts.callback.call(opts.scope || window, true, { result: out, has_fail: failed });
				}
			});
		});
		return true;
	},
	injectInfo: function () {
		var info = { path: "entry.cgi", minVersion: 1, maxVersion: 4 };
		var targets = [];
		if (window.SYNO && SYNO.API) {
			targets.push(SYNO.API.info, SYNO.API.Info, SYNO.API._info);
			if (SYNO.API.Info && SYNO.API.Info.knowns) { targets.push(SYNO.API.Info.knowns); }
		}
		if (window._S) { targets.push(_S.knowns, _S.Info); }
		Ext.each(this.apis, function (api) {
			Ext.each(targets, function (obj) {
				if (obj && typeof obj === "object" && !obj[api]) {
					obj[api] = info;
				}
			});
		});
	},
	download: function (opts) {
		var api = opts.api || (opts.webapi && opts.webapi.api);
		var method = opts.method || (opts.webapi && opts.webapi.method) || "backup";
		var version = opts.version || (opts.webapi && opts.webapi.version) || 1;
		var params = opts.params || (opts.webapi && opts.webapi.params) || {};
		var q = Ext.urlEncode(Ext.apply({ api: api, method: method, version: version }, this.encodeParams(params)));
		var a = document.createElement("a");
		a.href = this.base() + "?" + q;
		a.download = "threatprevention-backup.json";
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		if (opts.callback) {
			opts.callback.call(opts.scope || window, true, {});
		}
		return true;
	},
	install: function () {
		var me = this;
		me.injectInfo();
		function hookProto(cls, name, extra) {
			if (!cls || !cls.prototype || !cls.prototype[name] || cls.prototype[name]._tpsBridge) { return; }
			var orig = cls.prototype[name];
			cls.prototype[name] = function (opts) {
				if (extra) { return extra.call(this, opts, orig); }
				var self = this;
				var hit = me.dispatch(opts, function () { return orig.apply(self, arguments); }, self);
				if (hit === true) { return; }
				return orig.apply(this, arguments);
			};
			cls.prototype[name]._tpsBridge = true;
		}
		hookProto(SYNO.SDS.AppWindow, "sendWebAPI");
		hookProto(SYNO.SDS.AppWindow, "downloadWebAPI", function (opts, orig) {
			var api = opts && (opts.api || (opts.webapi && opts.webapi.api));
			if (me.isTps(api)) { return me.download(opts); }
			return orig.apply(this, arguments);
		});
		if (SYNO.SDS.AppWindow && SYNO.SDS.AppWindow.prototype.pollReg && !SYNO.SDS.AppWindow.prototype.pollReg._tpsBridge) {
			var origPoll = SYNO.SDS.AppWindow.prototype.pollReg;
			var origUnreg = SYNO.SDS.AppWindow.prototype.pollUnreg;
			SYNO.SDS.AppWindow.prototype.pollReg = function (opts) {
				var api = opts && opts.webapi && opts.webapi.api;
				if (!me.isTps(api)) { return origPoll.apply(this, arguments); }
				var self = this;
				var tick = function () {
					me.call(
						opts.webapi.api,
						opts.webapi.method,
						opts.webapi.version,
						opts.webapi.params || {},
						opts.status_callback || opts.callback,
						opts.scope || self
					);
				};
				if (opts.immediate !== false) { tick(); }
				return window.setInterval(tick, (opts.interval || 5) * 1000);
			};
			SYNO.SDS.AppWindow.prototype.pollReg._tpsBridge = true;
			if (origUnreg && !origUnreg._tpsBridge) {
				SYNO.SDS.AppWindow.prototype.pollUnreg = function (id) {
					if (id) { window.clearInterval(id); }
					try { return origUnreg.apply(this, arguments); } catch (e) { return; }
				};
				SYNO.SDS.AppWindow.prototype.pollUnreg._tpsBridge = true;
			}
		}
		if (window.SYNO && SYNO.API && SYNO.API.Request && !SYNO.API.Request._tpsBridge) {
			var origReq = SYNO.API.Request;
			SYNO.API.Request = function (opts) {
				if (opts && me.isTps(opts.api)) {
					return me.dispatch(opts, function () { return origReq.apply(this, arguments); }, this);
				}
				return origReq.apply(this, arguments);
			};
			SYNO.API.Request._tpsBridge = true;
		}
		if (Ext.Ajax && Ext.Ajax.request && !Ext.Ajax.request._tpsBridge) {
			var origAjax = Ext.Ajax.request;
			Ext.Ajax.request = function (opts) {
				opts = opts || {};
				if (opts._tpsDirect) { return origAjax.apply(this, arguments); }
				var p = opts.params || {};
				var api = p.api || opts.api;
				if (me.isTps(api)) {
					return me.call(api, p.method || opts.method, p.version || 1, p, opts.success && function (ok, data, raw) {
						if (ok && opts.success) {
							opts.success.call(opts.scope || window, { responseText: Ext.encode(raw) }, opts);
						} else if (opts.failure) {
							opts.failure.call(opts.scope || window, { responseText: Ext.encode(raw), status: 500 }, opts);
						}
					}, opts.scope);
				}
				return origAjax.apply(this, arguments);
			};
			Ext.Ajax.request._tpsBridge = true;
		}
	}
};

Ext.onReady(function () {
	SYNO.SDS.TPS.Bridge.install();
	window.setTimeout(function () { SYNO.SDS.TPS.Bridge.install(); }, 400);
	window.setTimeout(function () { SYNO.SDS.TPS.Bridge.install(); }, 2000);
});
