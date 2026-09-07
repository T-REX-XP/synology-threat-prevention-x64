/* Research PoC compatibility layer, inlined into synoips.js at pack time.
   Official ExtJS talks to sendWebAPI / Store / pollReg. Those hit aarch64
   SYNO.TPS.*.so on SRM. Here they go to tpsweb via same-origin /api. */
Ext.namespace("SYNO.SDS.TPS");

SYNO.SDS.TPS.Bridge = {
	base: function () {
		return "/webman/3rdparty/ThreatPrevention/api";
	},
	fallbackBase: function () {
		if (window.location.protocol === "https:") { return ""; }
		return "http://" + (window.location.hostname || "127.0.0.1") + ":19557/";
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
	envelope: function (j) {
		var data = (j && j.data) || {};
		var out = Ext.apply({ success: !!(j && j.success), data: data }, data);
		if (j && j.error) { out.error = j.error; }
		return out;
	},
	call: function (api, method, version, params, cb, scope) {
		var me = this;
		var q = Ext.apply({ api: api, method: method, version: version || 1 }, this.encodeParams(params));
		function fire(ok, j) {
			if (cb) { cb.call(scope || window, ok, (j && j.data) || {}, j || {}, q); }
		}
		function post(url, then404) {
			Ext.Ajax.request({
				url: url,
				method: "POST",
				params: q,
				_tpsDirect: true,
				success: function (resp) {
					var j = {};
					try { j = Ext.decode(resp.responseText); } catch (e) { j = { success: false }; }
					fire(!!j.success, j);
				},
				failure: function (resp) {
					if (then404 && resp && (resp.status === 404 || resp.status === 0)) {
						then404();
						return;
					}
					fire(false, { success: false, error: { code: 500 } });
				}
			});
		}
		var alt = me.fallbackBase();
		post(me.base(), alt ? function () { post(alt); } : null);
	},
	isTps: function (api) {
		return api && String(api).indexOf("SYNO.TPS.") === 0;
	},
	passthrough: function (item, cb, scope) {
		Ext.Ajax.request({
			url: "/webapi/entry.cgi",
			method: "POST",
			params: Ext.apply({
				api: item.api,
				method: item.method,
				version: item.version || 1
			}, this.encodeParams(item.params || {})),
			_tpsDirect: true,
			success: function (resp) {
				var j = {};
				try { j = Ext.decode(resp.responseText); } catch (e) { j = { success: false }; }
				if (cb) { cb.call(scope || window, !!j.success, j.data || {}, j); }
			},
			failure: function () {
				if (cb) { cb.call(scope || window, false, {}, { success: false, error: { code: 500 } }); }
			}
		});
	},
	dispatch: function (opts, fallback) {
		if (!opts) { return fallback(); }
		if (opts.compound && opts.compound.params) {
			return this.compound(opts);
		}
		var api = opts.api || (opts.webapi && opts.webapi.api);
		var method = opts.method || (opts.webapi && opts.webapi.method);
		var version = opts.version || (opts.webapi && opts.webapi.version) || 1;
		var params = opts.params || (opts.webapi && opts.webapi.params) || {};
		if (!this.isTps(api)) {
			return fallback();
		}
		this.call(api, method, version, params, opts.callback || opts.status_callback, opts.scope);
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
		function done(idx, ok, data, raw) {
			out[idx] = { api: items[idx].api, method: items[idx].method, success: ok, data: data };
			if (!ok) {
				failed = true;
				out[idx].error = (raw && raw.error) || { code: 500 };
			}
			left -= 1;
			if (!left && opts.callback) {
				opts.callback.call(opts.scope || window, true, { result: out, has_fail: failed });
			}
		}
		Ext.each(items, function (item, idx) {
			if (me.isTps(item.api)) {
				me.call(item.api, item.method, item.version || 1, item.params || {}, function (ok, data, raw) {
					done(idx, ok, data, raw);
				});
			} else {
				me.passthrough(item, function (ok, data, raw) { done(idx, ok, data, raw); });
			}
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
				if (obj && typeof obj === "object" && !obj[api]) { obj[api] = info; }
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
		if (opts.callback) { opts.callback.call(opts.scope || window, true, {}); }
		return true;
	},
	pickApi: function (opts) {
		var p = (opts && (opts.params || opts.jsonData)) || {};
		return p.api || (opts && opts.api) || "";
	},
	install: function () {
		var me = this;
		if (me._installed) {
			me.injectInfo();
			return;
		}
		me.injectInfo();
		function hookProto(cls, name, extra) {
			if (!cls || !cls.prototype || !cls.prototype[name] || cls.prototype[name]._tpsBridge) { return; }
			var orig = cls.prototype[name];
			cls.prototype[name] = function () {
				var args = arguments;
				var opts = args[0];
				if (extra) { return extra.call(this, opts, orig, args); }
				var hit = me.dispatch(opts, function () { return orig.apply(this, args); }.bind(this));
				if (hit === true) { return; }
				return orig.apply(this, args);
			};
			cls.prototype[name]._tpsBridge = true;
		}
		hookProto(SYNO.SDS.AppWindow, "sendWebAPI");
		if (SYNO.SDS.AppInstance) { hookProto(SYNO.SDS.AppInstance, "sendWebAPI"); }
		hookProto(SYNO.SDS.AppWindow, "downloadWebAPI", function (opts, orig, args) {
			var api = opts && (opts.api || (opts.webapi && opts.webapi.api));
			if (me.isTps(api)) { return me.download(opts); }
			return orig.apply(this, args);
		});
		if (SYNO.SDS.AppWindow && SYNO.SDS.AppWindow.prototype.pollReg && !SYNO.SDS.AppWindow.prototype.pollReg._tpsBridge) {
			var origPoll = SYNO.SDS.AppWindow.prototype.pollReg;
			var origUnreg = SYNO.SDS.AppWindow.prototype.pollUnreg;
			SYNO.SDS.AppWindow.prototype.pollReg = function (opts) {
				var args = arguments;
				var api = opts && opts.webapi && opts.webapi.api;
				if (!me.isTps(api)) { return origPoll.apply(this, args); }
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
				var args = arguments;
				if (opts && me.isTps(opts.api)) {
					return me.dispatch(opts, function () { return origReq.apply(this, args); });
				}
				return origReq.apply(this, args);
			};
			SYNO.API.Request._tpsBridge = true;
		}
		if (Ext.Ajax && Ext.Ajax.request && !Ext.Ajax.request._tpsBridge) {
			var origAjax = Ext.Ajax.request;
			Ext.Ajax.request = function (opts) {
				opts = opts || {};
				if (opts._tpsDirect) { return origAjax.apply(this, arguments); }
				var api = me.pickApi(opts);
				if (!me.isTps(api)) { return origAjax.apply(this, arguments); }
				var p = opts.params || opts.jsonData || {};
				return me.call(api, p.method || opts.method, p.version || 1, p, function (ok, data, raw) {
					var env = me.envelope(raw || { success: ok, data: data });
					var fake = { responseText: Ext.encode(env), status: ok ? 200 : 500 };
					if (ok && opts.success) {
						opts.success.call(opts.scope || window, fake, opts);
					} else if (!ok && opts.failure) {
						opts.failure.call(opts.scope || window, fake, opts);
					}
				});
			};
			Ext.Ajax.request._tpsBridge = true;
		}
		me._installed = true;
	}
};

(function () {
	function boot() {
		if (window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Bridge) {
			SYNO.SDS.TPS.Bridge.install();
		}
	}
	if (window.Ext && Ext.onReady) {
		if (Ext.isReady) { boot(); }
		Ext.onReady(boot);
	} else {
		window.setTimeout(boot, 0);
	}
}());
