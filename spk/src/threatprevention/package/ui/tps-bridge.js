/* Research PoC compatibility layer, inlined into synoips.js at pack time.
   Official ExtJS talks to sendWebAPI / Store / pollReg. Those hit aarch64
   SYNO.TPS.*.so on SRM. Here they go to tpsweb via same-origin /webman/tps-api. */
window.SYNO = window.SYNO || {};
SYNO.SDS = SYNO.SDS || {};
SYNO.SDS.TPS = SYNO.SDS.TPS || {};
SYNO.SDS.Chart = SYNO.SDS.Chart || {};
if (window.Ext && Ext.namespace) {
	Ext.namespace("SYNO.SDS.TPS");
	Ext.namespace("SYNO.SDS.Chart");
}

/* DSM 7 desktop has no SYNO.SDS.Chart.* (those are SRM widgets). Stub enough
   for TrendsGraphComponent / TopNPieChartPanel constructors to finish. */
(function () {
	if (!window.Ext || !Ext.extend) { return; }
	if (SYNO.SDS.Chart.LineChart && SYNO.SDS.Chart.LineChart.prototype && SYNO.SDS.Chart.LineChart.prototype.setChartItems) {
		return;
	}
	SYNO.SDS.Chart.CreateAxis = SYNO.SDS.Chart.CreateAxis || function (cfg) {
		return Ext.apply({ type: "default", ticks: 0, tickPadding: 0, max: 0, tickFormatter: Ext.emptyFn }, cfg || {});
	};
	var Base = Ext.BoxComponent || Ext.Component;
	if (!Base) { return; }
	SYNO.SDS.Chart.LineChart = Ext.extend(Base, {
		constructor: function (cfg) {
			cfg = cfg || {};
			this.chartItems = [];
			this.axisX = SYNO.SDS.Chart.CreateAxis({});
			this.axisY = SYNO.SDS.Chart.CreateAxis({ max: 0 });
			this.chartPaddings = cfg.chartPaddings || { top: 6, right: 0, bottom: 22, left: 38 };
			this.trackFormatter = Ext.emptyFn;
			SYNO.SDS.Chart.LineChart.superclass.constructor.call(this, Ext.apply({
				autoEl: { tag: "div", cls: "syno-sds-tps-linechart", style: "width:100%;height:" + (cfg.height || 210) + "px;background:#F5F7FA;" }
			}, cfg));
		},
		setChartItems: function (items) {
			this.chartItems = items || [];
			var max = 0;
			Ext.each(this.chartItems, function (series) {
				Ext.each(series.data || [], function (pt) {
					var y = Ext.isArray(pt) ? Number(pt[1]) || 0 : Number(pt && pt.y) || 0;
					if (y > max) { max = y; }
				});
			});
			this.axisY = this.axisY || {};
			this.axisY.max = max || 1;
		},
		draw: function () {
			if (!this.el || !this.el.dom) { return; }
			var w = this.el.getWidth() || 400, h = this.el.getHeight() || 210;
			var pad = this.chartPaddings || {};
			var left = pad.left || 38, bottom = pad.bottom || 22, top = pad.top || 6, right = pad.right || 0;
			var iw = Math.max(10, w - left - right), ih = Math.max(10, h - top - bottom);
			var max = (this.axisY && this.axisY.max) || 1;
			var paths = [];
			Ext.each(this.chartItems, function (series) {
				var pts = series.data || [];
				if (!pts.length) { return; }
				var n = pts.length;
				var d = [];
				Ext.each(pts, function (pt, i) {
					var x = left + (n <= 1 ? iw / 2 : (iw * i / (n - 1)));
					var yv = Ext.isArray(pt) ? Number(pt[1]) || 0 : 0;
					var y = top + ih - (ih * yv / max);
					d.push((i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1));
				});
				paths.push('<path d="' + d.join(" ") + '" fill="none" stroke="' + (series.color || "#2A588C") + '" stroke-width="' + (series.width || 2) + '"/>');
			});
			this.el.update('<svg width="' + w + '" height="' + h + '" xmlns="http://www.w3.org/2000/svg">' + paths.join("") + "</svg>");
		}
	});
	SYNO.SDS.Chart.PieChart = Ext.extend(Base, {
		constructor: function (cfg) {
			cfg = cfg || {};
			this.chartItems = cfg.chartItems || [];
			SYNO.SDS.Chart.PieChart.superclass.constructor.call(this, Ext.apply({
				autoEl: { tag: "div", cls: "syno-sds-tps-piechart", style: "width:" + (cfg.width || 128) + "px;height:" + (cfg.height || 136) + "px;" }
			}, cfg));
			this.on("afterrender", this.draw, this);
		},
		draw: function () {
			if (!this.el || !this.el.dom) { return; }
			var items = this.chartItems || [];
			var total = 0;
			Ext.each(items, function (it) { total += Number(it.data) || 0; });
			var r = this.initialConfig.radius || 58;
			var ir = this.initialConfig.innerRadius || 20;
			var cx = (this.initialConfig.width || 128) / 2, cy = (this.initialConfig.height || 136) / 2;
			var a0 = -Math.PI / 2, parts = [];
			Ext.each(items, function (it) {
				var frac = total ? (Number(it.data) || 0) / total : 0;
				var a1 = a0 + frac * Math.PI * 2;
				var x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
				var x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
				var large = frac > 0.5 ? 1 : 0;
				parts.push('<path d="M ' + cx + " " + cy + " L " + x0.toFixed(1) + " " + y0.toFixed(1) + " A " + r + " " + r + " 0 " + large + " 1 " + x1.toFixed(1) + " " + y1.toFixed(1) + ' Z" fill="' + (it.color || "#2A588C") + '"/>');
				a0 = a1;
			});
			this.el.update('<svg width="' + (this.initialConfig.width || 128) + '" height="' + (this.initialConfig.height || 136) + '">' + parts.join("") + '<circle cx="' + cx + '" cy="' + cy + '" r="' + ir + '" fill="#fff"/></svg>');
		}
	});
}());


SYNO.SDS.TPS.Bridge = {
	base: function () {
		return "/webman/tps-api";
	},
	legacyBase: function () {
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
		"SYNO.TPS.Settings.Telegram", "SYNO.TPS.Settings.Feed", "SYNO.TPS.Settings.Map",
		"SYNO.TPS.Signature", "SYNO.TPS.Signature.Classification", "SYNO.TPS.Signature.Policy",
		"SYNO.TPS.Signature.Rule", "SYNO.TPS.Statistic.Device", "SYNO.TPS.Statistic.Trends",
		"SYNO.Core.Network.NSM.Device", "SYNO.Core.SystemDB",
		"SYNO.Core.ExternalDevice.Storage.USB"
	],
	compat: [
		"SYNO.Core.Network.NSM.Device",
		"SYNO.Core.SystemDB",
		"SYNO.Core.ExternalDevice.Storage.USB"
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
			try {
				if (cb) { cb.call(scope || window, ok, (j && j.data) || {}, j || {}, q); }
			} catch (e) {
				if (window.console && console.error) { console.error("SYNO.TPS callback", e); }
			}
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
		post(me.base(), function () {
			post(me.legacyBase(), function () {
				var alt = me.fallbackBase();
				if (alt) { post(alt); } else { fire(false, { success: false, error: { code: 404 } }); }
			});
		});
	},
	isTps: function (api) {
		return api && String(api).indexOf("SYNO.TPS.") === 0;
	},
	isCompat: function (api) {
		return api && this.compat.indexOf(api) >= 0;
	},
	isHosted: function (api) {
		return this.isTps(api) || this.isCompat(api);
	},
	compoundHasHosted: function (compound) {
		var hit = false;
		Ext.each((compound && compound.params) || [], function (item) {
			if (item && this.isHosted(item.api)) { hit = true; }
		}, this);
		return hit;
	},
	isPollingCallback: function (cb) {
		if (!cb || typeof cb !== "function") { return false; }
		var name = cb.name || cb.displayName || "";
		if (String(name).toLowerCase().indexOf("polling") !== -1) { return true; }
		function same(obj) {
			if (!obj) { return false; }
			return cb === obj.pollingCompoundCallack ||
				cb === obj.pollingCompoundCallback ||
				cb === obj.callback;
		}
		var Req = window.SYNO && SYNO.API && SYNO.API.Request;
		if (same(Req && Req.Polling) || same(Req && Req.Polling && Req.Polling.prototype)) { return true; }
		var Entry = window.SYNO && SYNO.Entry && SYNO.Entry.Request;
		if (same(Entry && Entry.Polling) || same(Entry && Entry.Polling && Entry.Polling.prototype)) { return true; }
		return false;
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
			/* SYNO.API.Request is global. DSM desktop polling compounds also
			   use it; stealing those and calling back (ok, {result}) crashes
			   pollingCompoundCallack on data.reg_ref. Only hosted TPS compounds. */
			if (!this.compoundHasHosted(opts.compound)) { return fallback(); }
			if (this.isPollingCallback(opts.callback || opts.status_callback)) {
				return fallback();
			}
			return this.compound(opts);
		}
		var api = opts.api || (opts.webapi && opts.webapi.api);
		var method = opts.method || (opts.webapi && opts.webapi.method);
		var version = opts.version || (opts.webapi && opts.webapi.version) || 1;
		var params = opts.params || (opts.webapi && opts.webapi.params) || {};
		if (!this.isHosted(api)) {
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
			out[idx] = { api: items[idx].api, method: items[idx].method, success: ok, data: data || {} };
			if (!ok) {
				failed = true;
				out[idx].error = (raw && raw.error) || { code: 500 };
			}
			if (ok && items[idx].api === "SYNO.TPS.Notification" && items[idx].method === "set") {
				var panel = opts.scope;
				if (panel && panel.getForm && panel.getForm().findField("enable_telegram")) {
					me.saveTelegramFrom(panel);
				}
			}
			left -= 1;
			if (!left && opts.callback) {
				var payload = { result: out, has_fail: failed };
				if (me.isPollingCallback(opts.callback)) {
					opts.callback.call(opts.scope || window, {
						success: true,
						data: Ext.apply({
							reg_ref: (opts.reg_ref || (opts.compound && opts.compound.reg_ref) || "tps"),
							result: out,
							has_fail: failed
						}, payload)
					});
					return;
				}
				opts.callback.call(opts.scope || window, true, payload);
			}
		}
		Ext.each(items, function (item, idx) {
			if (item.api === "SYNO.TPS.Notification" && item.method === "set") {
				me.stripTelegramParams({params: item.params});
			}
			if (me.isHosted(item.api)) {
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
		function add(obj) {
			if (obj && typeof obj === "object") { targets.push(obj); }
		}
		if (window.SYNO && SYNO.API) {
			add(SYNO.API.info);
			add(SYNO.API.Info);
			add(SYNO.API._info);
			if (SYNO.API.Info && SYNO.API.Info.knowns) { add(SYNO.API.Info.knowns); }
			Ext.each([SYNO.API.Manager, SYNO.API.currentManager], function (mgr) {
				if (!mgr) { return; }
				if (!mgr.knownAPI) { mgr.knownAPI = {}; }
				add(mgr.knownAPI);
			});
		}
		if (window._S) {
			add(_S.knowns);
			add(_S.Info);
		}
		Ext.each(this.apis, function (api) {
			Ext.each(targets, function (obj) {
				if (obj) { obj[api] = info; }
			});
		});
	},
	injectModuleListCss: function () {
		/* Sprite frames: 0 gray, -24px blue, -48px white, -72px silver.
		   SRM selected chrome is dark so official CSS uses the white frame.
		   DSM 7 highlights with light blue, which hides that white icon. */
		if (document.getElementById("tps-modulelist-css")) { return; }
		var css = [
			".syno-sds-ips .syno-ux-modulelist .x-tree-node-icon { background-position: 0 0; }",
			".syno-sds-ips .syno-ux-modulelist .x-tree-node-over .x-tree-node-icon { background-position: 0 -24px !important; }",
			".syno-sds-ips .syno-ux-modulelist .x-tree-selected .x-tree-node-icon,",
			".syno-sds-ips .syno-ux-modulelist .x-tree-node-selected .x-tree-node-icon,",
			".syno-sds-ips .syno-ux-modulelist .x-tree-node-leaf.x-tree-selected .x-tree-node-icon,",
			".syno-sds-ips .syno-ux-modulelist .x-tree-node-leaf.x-tree-node-selected .x-tree-node-icon { background-position: 0 -24px !important; }"
		].join("\n");
		var el = document.createElement("style");
		el.id = "tps-modulelist-css";
		el.type = "text/css";
		if (el.styleSheet) { el.styleSheet.cssText = css; }
		else { el.appendChild(document.createTextNode(css)); }
		(document.head || document.getElementsByTagName("head")[0] || document.body).appendChild(el);
	},
	hookManagerRequest: function () {
		/* Settings Device loadForm → getForm().submit({compound})
		   → SYNO.API.Form.Action.Submit.run
		   → Manager.requestAjaxAPI(api, method, version, {compound}, params, cb)
		   → requestAjaxAPIv2 rewrites to SYNO.Entry.Request and POSTs entry.cgi.
		   DSM 7 has neither SYNO.TPS.Device nor SYNO.Core.Network.NSM.Device, so
		   the compound comes back has_fail / "No Such API" and the grid never
		   loadData(). queryAPI("all") also replaces Manager.knownAPI and would
		   drop catalog entries. Host those APIs on tpsweb and intercept here. */
		var me = this;
		var hostedInfo = { path: "entry.cgi", minVersion: 1, maxVersion: 4 };
		function fire(cb, scope, ok, data, raw) {
			var envelope = data || {};
			var fake = {
				status: ok ? 200 : 500,
				responseData: envelope,
				responseText: Ext.encode({ success: !!ok, data: envelope })
			};
			if (cb) { cb.call(scope || window, ok, envelope, envelope, {}, fake); }
		}
		function hostedCompound(compound) {
			var hit = false;
			if (!compound || !compound.params) { return false; }
			Ext.each(compound.params, function (item) {
				if (item && me.isHosted(item.api)) { hit = true; }
			});
			return hit;
		}
		function pickCompound() {
			var i, cfg, found = null;
			for (i = 0; i < arguments.length; i++) {
				cfg = arguments[i];
				if (!cfg || typeof cfg !== "object") { continue; }
				if (cfg.webapi && cfg.webapi.compound && cfg.webapi.compound.params) {
					found = cfg.webapi.compound;
				}
				if (cfg.compound && cfg.compound.params) { found = cfg.compound; }
			}
			return found;
		}
		function intercept(api, method, version, opts, params, cb, scope) {
			var compound = pickCompound(api, opts, params);
			var cfg = (api && typeof api === "object" && !Ext.isString(api)) ? (api.webapi || api) : null;
			if (!cb && cfg) { cb = cfg.callback || api.callback; }
			if (!cb && opts) { cb = opts.callback; }
			if (!scope && cfg) { scope = cfg.scope || api.scope; }
			if (!scope && opts) { scope = opts.scope; }
			if (hostedCompound(compound)) {
				if (me.isPollingCallback(cb) || me.isPollingCallback(opts && opts.callback) ||
						me.isPollingCallback(cfg && cfg.callback)) {
					return false;
				}
				me.compound({
					compound: compound,
					scope: scope,
					callback: function (ok, data) { fire(cb, scope, ok, data); }
				});
				return true;
			}
			if (cfg && !compound && me.isHosted(cfg.api)) {
				me.call(cfg.api, cfg.method, cfg.version || 1, cfg.params || {}, function (ok, data, raw) {
					fire(cb, scope, ok, data, raw);
				});
				return true;
			}
			if (me.isHosted(api)) {
				me.call(api, method, version || 1, params || (opts && opts.params) || {}, function (ok, data, raw) {
					fire(cb, scope, ok, data, raw);
				});
				return true;
			}
			return false;
		}
		function wrapRequest(obj) {
			if (!obj) { return; }
			Ext.each(["requestAjaxAPI", "requestAjaxAPIv2", "requestAPI"], function (name) {
				if (typeof obj[name] !== "function" || obj[name]._tpsBridge) { return; }
				(function (key) {
					var orig = obj[key];
					obj[key] = function (api, method, version, opts, params, cb, scope, http) {
						if (intercept(api, method, version, opts, params, cb, scope)) { return true; }
						return orig.apply(this, arguments);
					};
					obj[key]._tpsBridge = true;
				}(name));
			});
		}
		function wrapQuery(obj) {
			if (!obj || typeof obj.queryAPI !== "function" || obj.queryAPI._tpsBridge) { return; }
			var orig = obj.queryAPI;
			obj.queryAPI = function (api, cb, scope) {
				return orig.call(this, api, function () {
					me.injectInfo();
					if (cb) { cb.apply(scope || this, arguments); }
				}, scope);
			};
			obj.queryAPI._tpsBridge = true;
		}
		function wrapKnown(obj) {
			if (!obj) { return; }
			Ext.each(["getKnownAPI", "getKnownAPIv2"], function (name) {
				if (typeof obj[name] !== "function" || obj[name]._tpsBridge) { return; }
				(function (key) {
					var orig = obj[key];
					obj[key] = function (api, extra) {
						var name = api;
						if (api && typeof api === "object") { name = api.api; }
						var info = orig.apply(this, arguments);
						if (!info && me.isHosted(name)) { return hostedInfo; }
						return info;
					};
					obj[key]._tpsBridge = true;
				}(name));
			});
		}
		function hookObj(obj) {
			if (!obj) { return; }
			wrapRequest(obj);
			wrapQuery(obj);
			wrapKnown(obj);
			if (obj.prototype) {
				wrapRequest(obj.prototype);
				wrapQuery(obj.prototype);
				wrapKnown(obj.prototype);
			}
		}
		if (window.SYNO && SYNO.API) {
			hookObj(SYNO.API._Manager);
			hookObj(SYNO.API.Manager);
			hookObj(SYNO.API.currentManager);
			if (SYNO.API.GetKnownAPI && !SYNO.API.GetKnownAPI._tpsBridge) {
				var origGet = SYNO.API.GetKnownAPI;
				SYNO.API.GetKnownAPI = function (api, extra) {
					var info = origGet.apply(this, arguments);
					if (!info && me.isHosted(api)) { return hostedInfo; }
					return info;
				};
				SYNO.API.GetKnownAPI._tpsBridge = true;
			}
		}
		me.injectInfo();
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
	adminList: function (ids) {
		var admin = ids || [];
		admin.size = function () { return this.length; };
		return { admin: admin };
	},
	looksOfficialHtml: function (v) {
		return typeof v === "string" && v.indexOf("<") !== -1 &&
			(v.indexOf("pathlink") !== -1 || v.indexOf("<font") !== -1 ||
				v.indexOf("<a ") !== -1 || v.indexOf("<a>") !== -1 ||
				v.indexOf("font-order") !== -1 ||
				v.indexOf("syno-sds-ips-event-") !== -1 ||
				v.indexOf('class="syno-sds-ips') !== -1 ||
				v.indexOf("note-font") !== -1 ||
				v.indexOf("syno-ux-note") !== -1 ||
				v.indexOf("color-block") !== -1 ||
				v.indexOf("font-percentage") !== -1 ||
				v.indexOf("<span ") !== -1 ||
				v.indexOf("<div ") !== -1);
	},
	restoreOfficialLabel: function (field) {
		var html = field && field.fieldLabel;
		if (!this.looksOfficialHtml(html)) { return; }
		var sep = field.labelSeparator;
		if (sep === undefined || sep === null) { sep = ""; }
		var markup = html + sep;
		var node = null;
		try {
			node = this.findOfficialLabelNode(field);
		} catch (e) {
			node = null;
		}
		if (node) { node.innerHTML = markup; }
	},
	restoreOfficialValue: function (field) {
		var v = field && (field.value !== undefined ? field.value : field.getValue && field.getValue());
		if (!this.looksOfficialHtml(v)) { return; }
		var el = field.el && field.el.dom;
		if (!el && field.getEl) {
			var wrap = field.getEl();
			el = wrap && wrap.dom;
		}
		if (!el) { return; }
		/* Rewriting live markup drops Ext listeners official afterrender just
		   attached to <a class="pathlink">. Skip when tags are already real. */
		if (el.querySelector && el.querySelector("a.pathlink, a, font")) {
			var cur = el.innerHTML || "";
			if (cur.indexOf("<") !== -1 && cur.indexOf("&lt;") === -1) { return; }
		}
		el.innerHTML = v;
	},
	restoreOfficialMarkup: function (field) {
		this.restoreOfficialLabel(field);
		this.restoreOfficialValue(field);
	},
	findOfficialLabelNode: function (field) {
		/* Ext 3.4 Element.up → findParentNode does this.dom.parentNode with no
		   null check. PercentageField afterrender can run while el exists as an
		   Element wrapper but el.dom is still unset (or already cleared). */
		function nodeOf(x) {
			if (!x) { return null; }
			if (x.nodeType === 1) { return x; }
			return (x.dom && x.dom.nodeType === 1) ? x.dom : null;
		}
		function firstLabel(root) {
			var n = nodeOf(root);
			if (!n || !n.querySelector) { return null; }
			return n.querySelector("label.x-form-item-label") ||
				n.querySelector(".x-form-item-label") ||
				n.querySelector("label");
		}
		function closestFormItem(el) {
			var p = nodeOf(el);
			while (p && p.nodeType === 1) {
				var cn = " " + (p.className || "") + " ";
				if (cn.indexOf(" x-form-item ") !== -1) { return p; }
				p = p.parentNode;
			}
			return null;
		}
		function fromAnchor(el) {
			var start = nodeOf(el), p, sib, hit;
			if (!start) { return null; }
			hit = firstLabel(closestFormItem(start));
			if (hit) { return hit; }
			sib = start.previousSibling;
			while (sib) {
				if (sib.nodeType === 1 && (sib.tagName === "LABEL" ||
						(sib.className && String(sib.className).indexOf("label") !== -1))) {
					return sib;
				}
				sib = sib.previousSibling;
			}
			p = start.parentNode;
			return firstLabel(p) || firstLabel(p && p.parentNode);
		}
		var found = nodeOf(field.labelEl);
		if (found && found.tagName === "LABEL") { return found; }
		found = firstLabel(field.labelEl) || firstLabel(field.itemCt) ||
			firstLabel(field.container);
		if (found) { return found; }
		var id = field.id;
		if (id && document.getElementById) {
			found = document.getElementById(id + "-labelEl");
			if (found) { return found; }
			found = document.getElementById("x-form-el-" + id);
			if (found) {
				found = firstLabel(closestFormItem(found) || found.parentNode) ||
					firstLabel(found);
				if (found) { return found; }
			}
			try {
				found = document.querySelector('label[for="' + String(id).replace(/\\/g, "").replace(/"/g, "") + '"]');
				if (found) { return found; }
			} catch (e) { /* ignore bad id */ }
		}
		return fromAnchor(field.el) || fromAnchor(field.container) ||
			fromAnchor(field.getEl && field.getEl());
	},
	patchDisplayHtml: function () {
		/* Official Overview injects <a class="pathlink"> into syno_displayfield.
		   SRM rendered that HTML. DSM 7 encodes it, so the link is visible as
		   text and afterrender does b.el.down("a").on(...) on null.
		   Restoring innerHTML after that bind also drops the listener — see
		   patchOverviewPathlinks. Statistics TopNPercentPanel puts
		   <font class="font-order"> in fieldLabel (not value); DSM 7 encodes that too. */
		var me = this;
		var seen = [];
		function patch(Cls) {
			if (!Cls || !Cls.prototype || Cls.prototype._tpsHtml || seen.indexOf(Cls) !== -1) { return; }
			seen.push(Cls);
			var proto = Cls.prototype;
			var origInit = proto.initComponent;
			proto.initComponent = function () {
				var v = (this.initialConfig && this.initialConfig.value) || this.value;
				var label = (this.initialConfig && this.initialConfig.fieldLabel) || this.fieldLabel;
				var field = this;
				if (me.looksOfficialHtml(v)) { this.htmlEncode = false; }
				if (origInit) { origInit.apply(this, arguments); }
				if (me.looksOfficialHtml(this.value || v)) { this.htmlEncode = false; }
				if (me.looksOfficialHtml(this.fieldLabel || label) ||
						me.looksOfficialHtml(this.value || v)) {
					this.on("afterrender", function () {
						me.restoreOfficialMarkup(field);
						window.setTimeout(function () { me.restoreOfficialMarkup(field); }, 0);
					}, this);
				}
			};
			var origRaw = proto.setRawValue;
			if (origRaw) {
				proto.setRawValue = function (v) {
					if (me.looksOfficialHtml(v) || me.looksOfficialHtml(this.value)) {
						this.htmlEncode = false;
					}
					return origRaw.apply(this, arguments);
				};
			}
			var origSet = proto.setValue;
			proto.setValue = function (v) {
				if (me.looksOfficialHtml(v)) { this.htmlEncode = false; }
				if (origSet) { return origSet.apply(this, arguments); }
				this.value = v;
				if (this.rendered && this.el) { this.el.update(this.htmlEncode ? Ext.util.Format.htmlEncode(v) : v); }
			};
			var origRender = proto.onRender;
			if (origRender) {
				proto.onRender = function () {
					if (me.looksOfficialHtml(this.value) ||
							me.looksOfficialHtml(this.initialConfig && this.initialConfig.value)) {
						this.htmlEncode = false;
					}
					var ret = origRender.apply(this, arguments);
					if (me.looksOfficialHtml(this.value)) {
						me.restoreOfficialValue(this);
					}
					return ret;
				};
			}
			var origSetLabel = proto.setFieldLabel;
			if (origSetLabel) {
				proto.setFieldLabel = function (label) {
					var ret = origSetLabel.apply(this, arguments);
					if (me.looksOfficialHtml(label || this.fieldLabel)) {
						me.restoreOfficialLabel(this);
					}
					return ret;
				};
			}
			proto._tpsHtml = true;
		}
		function patchFormLayout(Layout) {
			if (!Layout || !Layout.prototype || Layout.prototype._tpsLabelHtml) { return; }
			var orig = Layout.prototype.getTemplateArgs;
			if (!orig) { return; }
			Layout.prototype.getTemplateArgs = function (field) {
				var args = orig.apply(this, arguments);
				if (args && field && me.looksOfficialHtml(field.fieldLabel)) {
					args.label = field.fieldLabel;
					args.fieldLabel = field.fieldLabel;
				}
				return args;
			};
			Layout.prototype._tpsLabelHtml = true;
		}
		patch(window.SYNO && SYNO.ux && SYNO.ux.DisplayField);
		patch(window.Ext && Ext.form && Ext.form.DisplayField);
		if (window.Ext && Ext.ComponentMgr && Ext.ComponentMgr.types) {
			patch(Ext.ComponentMgr.types.syno_displayfield);
			patch(Ext.ComponentMgr.types.displayfield);
		}
		if (window.Ext && Ext.layout) {
			patchFormLayout(Ext.layout.FormLayout);
			if (Ext.layout.container) { patchFormLayout(Ext.layout.container.Form); }
		}
	},
	patchPercentLabels: function () {
		/* Top 5 Source/Dest IPs use PercentageField({fieldLabel: '<font class="font-order">…'}).
		   DSM 7 htmlEncodes form labels; restore after render. */
		var me = this;
		var tries = 0;
		function attach() {
			var Cls = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Event &&
				SYNO.SDS.TPS.Event.PercentageField;
			if (!Cls || !Cls.prototype) {
				if (tries++ < 40) { window.setTimeout(attach, 100); }
				return;
			}
			if (Cls.prototype._tpsPctLabel) { return; }
			var orig = Cls.prototype.afterRender;
			Cls.prototype.afterRender = function () {
				var field = this;
				if (orig) { orig.apply(this, arguments); }
				else if (Cls.superclass && Cls.superclass.afterRender) {
					Cls.superclass.afterRender.apply(this, arguments);
				}
				me.restoreOfficialMarkup(this);
				window.setTimeout(function () { me.restoreOfficialMarkup(field); }, 0);
			};
			Cls.prototype._tpsPctLabel = true;
		}
		attach();
	},
	openTpsPage: function (win, pageFn, tabId) {
		if (!win) { return; }
		function callFirst(names, arg) {
			var i, fn;
			for (i = 0; i < names.length; i++) {
				fn = win[names[i]];
				if (typeof fn !== "function") { continue; }
				try { fn.call(win, arg); return true; } catch (e) { /* try next */ }
			}
			return false;
		}
		if (!callFirst(["selectPage", "openPage", "goToPage", "setActivePage", "activatePage"], pageFn)) {
			var list = win.moduleList || win.pageList || win.listPanel;
			var root = list && list.getRootNode && list.getRootNode();
			var node = root && root.findChild && root.findChild("fn", pageFn, true);
			if (node && list.selectPath && node.getPath) {
				try { list.selectPath(node.getPath()); } catch (e2) { /* ignore */ }
			} else if (node && list.fireEvent) {
				list.fireEvent("click", node);
			}
		}
		if (!tabId) { return; }
		var tries = 0;
		function applyTab() {
			if (typeof win.selectTab === "function") {
				try { win.selectTab(tabId); return true; } catch (e3) { /* fall through */ }
			}
			var page = (win.getActivePage && win.getActivePage()) ||
				(win.getPage && win.getPage(pageFn));
			if (!page && win.findBy) {
				var found = win.findBy(function (c) {
					return c && (c.itemId === pageFn || c.id === pageFn);
				});
				page = found && found[0];
			}
			if (page && page.setActiveTab) {
				var tab = (page.getComponent && page.getComponent(tabId)) || tabId;
				try { page.setActiveTab(tab); return true; } catch (e4) { return false; }
			}
			return false;
		}
		function poll() {
			if (applyTab() || ++tries > 20) { return; }
			window.setTimeout(poll, 50);
		}
		window.setTimeout(poll, 0);
	},
	bindStatusPathlinks: function (panel) {
		if (!panel) { return; }
		var el = panel.el || (panel.getEl && panel.getEl());
		var dom = el && (el.dom || (el.nodeType === 1 ? el : null));
		if (!dom) { return; }
		if (dom.querySelectorAll) {
			var nodes = dom.querySelectorAll("a.pathlink");
			var i;
			for (i = 0; i < nodes.length; i++) {
				nodes[i].style.cursor = "pointer";
				if (!nodes[i].getAttribute("href")) { nodes[i].setAttribute("href", "#"); }
			}
		}
		if (panel._tpsPathlinkBound) { return; }
		if (!dom.addEventListener) { return; }
		panel._tpsPathlinkBound = true;
		var me = this;
		dom.addEventListener("click", function (ev) {
			var t = ev.target || ev.srcElement;
			var a = t;
			while (a && a !== dom) {
				if (a.tagName === "A" && (" " + (a.className || "") + " ").indexOf(" pathlink ") !== -1) {
					break;
				}
				a = a.parentNode;
			}
			if (!a || a === dom) { return; }
			if (ev.preventDefault) { ev.preventDefault(); }
			if (ev.stopPropagation) { ev.stopPropagation(); }
			function txt(sec, key) {
				try { return panel.helper && panel.helper.T ? panel.helper.T(sec, key) : ""; }
				catch (e) { return ""; }
			}
			var updateNow = txt("updater", "update_now_btn");
			var newVer = txt("updater", "update_status_new_version_desc");
			var auto = txt("overview", "auto_update_isnot_set_desc");
			var note = txt("overview", "notification_isnot_set_desc");
			var linkText = a.textContent || a.innerText || "";
			if (updateNow && linkText.indexOf(updateNow) !== -1) {
				if (panel.startUpdate) { panel.startUpdate(); }
				return;
			}
			var html = "";
			var p = a;
			while (p && p !== dom) {
				html = p.innerHTML || html;
				if ((auto && html.indexOf(auto) !== -1) || (note && html.indexOf(note) !== -1) ||
						(newVer && html.indexOf(newVer) !== -1)) {
					break;
				}
				p = p.parentNode;
			}
			if ((newVer && html.indexOf(newVer) !== -1) ||
					(updateNow && html.indexOf(updateNow) !== -1)) {
				if (panel.startUpdate) { panel.startUpdate(); }
			} else if (auto && html.indexOf(auto) !== -1) {
				me.openTpsPage(panel.findAppWindow && panel.findAppWindow(),
					"SYNO.SDS.TPS.Settings.TabPanel",
					"SYNO.SDS.TPS.Settings.GeneralPanel");
			} else if (note && html.indexOf(note) !== -1) {
				me.openTpsPage(panel.findAppWindow && panel.findAppWindow(),
					"SYNO.SDS.TPS.Settings.TabPanel",
					"SYNO.SDS.TPS.Settings.NotificationPanel");
			}
		}, true);
	},
	patchOverviewPathlinks: function (Panel) {
		/* Official afterrender does b.el.down("a").on("click", …). DSM 7 may
		   encode the markup so down("a") is null; restoreOfficialMarkup then
		   rewrites innerHTML and drops any listener that did attach. Capture
		   on StatusPanel survives both. */
		var me = this;
		function tryPatch() {
			var P = Panel;
			if (!P || !P.prototype) {
				P = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Overview &&
					SYNO.SDS.TPS.Overview.StatusPanel;
			}
			if (!P || !P.prototype) { return false; }
			if (P.prototype._tpsPathlink) { return true; }
			P.prototype._tpsPathlink = true;
			var origAfter = P.prototype.afterRender;
			P.prototype.afterRender = function () {
				if (origAfter) { origAfter.apply(this, arguments); }
				me.bindStatusPathlinks(this);
			};
			var origShowStart = P.prototype.showStart;
			if (origShowStart) {
				P.prototype.showStart = function () {
					var self = this;
					var ret = origShowStart.apply(this, arguments);
					me.bindStatusPathlinks(this);
					window.setTimeout(function () { me.bindStatusPathlinks(self); }, 0);
					return ret;
				};
			}
			if (Ext.ComponentMgr && Ext.ComponentMgr.all && Ext.ComponentMgr.all.each) {
				Ext.ComponentMgr.all.each(function (c) {
					if (c instanceof P) { me.bindStatusPathlinks(c); }
				});
			}
			P.prototype.linkToGeneralSetting = function () {
				me.openTpsPage(this.findAppWindow && this.findAppWindow(),
					"SYNO.SDS.TPS.Settings.TabPanel",
					"SYNO.SDS.TPS.Settings.GeneralPanel");
			};
			P.prototype.linkToNotificationSetting = function () {
				me.openTpsPage(this.findAppWindow && this.findAppWindow(),
					"SYNO.SDS.TPS.Settings.TabPanel",
					"SYNO.SDS.TPS.Settings.NotificationPanel");
			};
			return true;
		}
		if (tryPatch()) { return; }
		if (Panel) { return; }
		var tries = 0;
		var id = window.setInterval(function () {
			if (tryPatch() || ++tries > 80) { window.clearInterval(id); }
		}, 25);
	},
	prepareGeneralForm: function (panel) {
		if (!panel || !panel.getForm) { return; }
		var me = this;
		var form = panel.getForm();
		if (!form) { return; }
		var use = form.findField("use_code");
		var code = form.findField("code");
		var isPro = use && use.getValue && use.getValue() === "etPro";
		if (code) {
			code.allowBlank = !isPro;
			if (!isPro && code.clearInvalid) { code.clearInvalid(); }
		}
		var weekday = form.findField("weekday");
		if (weekday) {
			weekday.allowBlank = true;
			if (weekday.clearInvalid) { weekday.clearInvalid(); }
		}
		function coerceCombo(field, fallback) {
			if (!field || !field.getValue) { return; }
			var v = field.getValue();
			if (v === "" || v === null || v === undefined) {
				if (field.setValue) { field.setValue(fallback); }
				me.snapFieldOriginal(field);
				return;
			}
			if (!field.findRecord) { return; }
			var vf = field.valueField || "value";
			if (field.findRecord(vf, v)) { return; }
			if (field.findRecord(vf, String(v))) { field.setValue(String(v)); }
			else {
				var n = Number(v);
				if (!isNaN(n) && field.findRecord(vf, n)) { field.setValue(n); }
			}
			me.snapFieldOriginal(field);
		}
		coerceCombo(form.findField("hour"), 2);
		coerceCombo(form.findField("minute"), 0);
		var weekdayVal = weekday && weekday.getValue && weekday.getValue();
		if (weekday && weekday.setValue && (weekdayVal === "daily" || weekdayVal === "" || weekdayVal == null)) {
			weekday.setValue("0,1,2,3,4,5,6");
			weekday.allowBlank = true;
			if (weekday.clearInvalid) { weekday.clearInvalid(); }
		}
		var store = panel.interfaceStore;
		if (!store) { return; }
		if (store.getCount() === 0) {
			store.loadData({
				interface_list: [{
					if_id: "ovs_eth0", enabled: true, status: "connected",
					type: "", additional: {}
				}]
			});
		}
		var any = false;
		store.each(function (rec) {
			if (rec && rec.get("enabled")) { any = true; }
		});
		if (!any && store.getCount()) {
			var rec = store.getAt(0);
			if (rec) {
				rec.set("enabled", true);
				if (rec.commit) { rec.commit(); }
			}
		}
	},
	snapFieldOriginal: function (fld) {
		if (!fld || typeof fld.getValue !== "function") { return; }
		var v = fld.getValue();
		fld.originalValue = v;
		if (fld.startValue !== undefined) { fld.startValue = v; }
		if (fld.wasDirty) { fld.wasDirty = false; }
	},
	clearGeneralDirty: function (panel, names) {
		var form = panel && panel.getForm && panel.getForm();
		if (!form) { return; }
		var me = this;
		function snap(fld) { me.snapFieldOriginal(fld); }
		if (names) {
			Ext.each(names, function (name) { snap(form.findField(name)); });
			return;
		}
		if (form.items && form.items.each) {
			form.items.each(snap);
		}
		Ext.each([
			"enable_sensor", "enable_prevention", "enable_auto_export_events_during_postupgrade",
			"network_security_mode", "auto_update", "weekday", "hour", "minute",
			"use_code", "code", "update_status", "last_updated"
		], function (name) { snap(form.findField(name)); });
		if (form.findFields) {
			Ext.each(form.findFields("network_security_mode") || [], snap);
		}
		var store = panel.interfaceStore;
		if (store) {
			store.each(function (rec) {
				if (rec && rec.commit) { rec.commit(); }
			});
			if (store.modified) { store.modified = []; }
		}
	},
	wrapGeneralFormValid: function (panel) {
		var me = this;
		var form = panel && panel.getForm && panel.getForm();
		if (!form || !form.isValid || form.isValid._tpsGeneral) { return; }
		var orig = form.isValid;
		form.isValid = function () {
			me.prepareGeneralForm(panel);
			return orig.apply(this, arguments);
		};
		form.isValid._tpsGeneral = true;
		me.prepareGeneralForm(panel);
	},
	patchGeneralSettings: function (Panel) {
		/* Official isValid requires an enabled monitored interface. Empty
		   interface_list (or a hidden ET Pro code with allowBlank:false)
		   shows "Some of your settings are invalid" and blocks Apply. */
		var me = this;
		function tryPatch() {
			var P = Panel;
			if (!P || !P.prototype) {
				P = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Settings &&
					SYNO.SDS.TPS.Settings.GeneralPanel;
			}
			if (!P || !P.prototype) { return false; }
			if (P.prototype._tpsGeneral) { return true; }
			P.prototype._tpsGeneral = true;
			var origFill = P.prototype.fillConfig;
			if (origFill) {
				P.prototype.fillConfig = function (a) {
					var cfg = origFill.apply(this, arguments);
					function walk(items) {
						Ext.each(items || [], function (item) {
							if (!item) { return; }
							if (item.name === "code" || item.name === "weekday") {
								item.allowBlank = true;
							}
							if (item.items) { walk(item.items); }
						});
					}
					walk(cfg && cfg.items);
					return cfg;
				};
			}
			var origExtend = P.prototype.extendFormValid;
			P.prototype.extendFormValid = function () {
				if (origExtend) { origExtend.apply(this, arguments); }
				me.wrapGeneralFormValid(this);
			};
			var origReturn = P.prototype.processReturnData;
			if (origReturn) {
				P.prototype.processReturnData = function () {
					var self = this;
					var ret = origReturn.apply(this, arguments);
					me.prepareGeneralForm(this);
					me.clearGeneralDirty(this);
					window.setTimeout(function () { me.clearGeneralDirty(self); }, 0);
					window.setTimeout(function () { me.clearGeneralDirty(self); }, 50);
					return ret;
				};
			}
			var origStatus = P.prototype.setUpdateStatus;
			if (origStatus) {
				P.prototype.setUpdateStatus = function () {
					var ret = origStatus.apply(this, arguments);
					me.clearGeneralDirty(this, ["update_status", "last_updated"]);
					return ret;
				};
			}
			var origLast = P.prototype.setLastUpdatedDate;
			if (origLast) {
				P.prototype.setLastUpdatedDate = function () {
					var ret = origLast.apply(this, arguments);
					me.clearGeneralDirty(this, ["last_updated"]);
					return ret;
				};
			}
			var origSchedDirty = P.prototype.CheckUpdateSettingsDirty;
			P.prototype.CheckUpdateSettingsDirty = function (form, apis) {
				/* Official only tests auto_update + the composite wrapper.
				   syno_schedulefield / hour / minute live inside the composite
				   and do not mark it dirty, so Schedule.set was skipped. */
				var dirty = false;
				Ext.each(["auto_update", "autoupdate_time_settings", "weekday", "hour", "minute"], function (name) {
					var fld = form && form.findField && form.findField(name);
					if (fld && fld.isDirty && fld.isDirty()) { dirty = true; }
				});
				if (!dirty && origSchedDirty) {
					return origSchedDirty.apply(this, arguments);
				}
				if (!dirty) {
					return this.skipSetAPI(apis, "SYNO.TPS.Settings.Update.Schedule");
				}
				return apis;
			};
			var origDirty = P.prototype.extendFormDirty;
			P.prototype.extendFormDirty = function () {
				if (origDirty) { origDirty.apply(this, arguments); }
				var panel = this;
				var form = this.getForm && this.getForm();
				if (!form || !form.isDirty || form.isDirty._tpsClean) { return; }
				var origIsDirty = form.isDirty;
				form.isDirty = function () {
					if (panel._tpsIgnoreDirty) { return false; }
					return origIsDirty.apply(this, arguments);
				};
				form.isDirty._tpsClean = true;
			};
			if (Ext.ComponentMgr && Ext.ComponentMgr.all && Ext.ComponentMgr.all.each) {
				Ext.ComponentMgr.all.each(function (c) {
					if (c instanceof P) { me.wrapGeneralFormValid(c); }
				});
			}
			return true;
		}
		if (tryPatch()) { return; }
		if (Panel) { return; }
		var tries = 0;
		var id = window.setInterval(function () {
			if (tryPatch() || ++tries > 80) { window.clearInterval(id); }
		}, 25);
	},
	injectSettingsTabs: function () {
		var me = this;
		function tryPatch() {
			var S = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Settings;
			if (!S || !S.TabPanel || !S.TabPanel.prototype || !S.NotificationPanel || !S.NotificationPanel.prototype) {
				return false;
			}
			me.patchNotificationTelegram(S.NotificationPanel);
			me.patchSettingsTabPanel(S.TabPanel);
			if (S.GeneralPanel) { me.patchGeneralSettings(S.GeneralPanel); }
			return true;
		}
		if (tryPatch()) { return; }
		var tries = 0;
		var id = window.setInterval(function () {
			if (tryPatch() || ++tries > 80) { window.clearInterval(id); }
		}, 25);
	},
	hookExtDefine: function () {
		var me = this;
		if (!window.Ext || !Ext.define || Ext.define._tpsHook) { return; }
		var orig = Ext.define;
		Ext.define = function (name) {
			var cls = orig.apply(this, arguments);
			if (name === "SYNO.SDS.TPS.Settings.NotificationPanel") {
				me.patchNotificationTelegram(cls);
			}
			if (name === "SYNO.SDS.TPS.Settings.TabPanel") {
				me.patchSettingsTabPanel(cls);
			}
			if (name === "SYNO.SDS.TPS.Overview.StatusPanel") {
				me.patchOverviewPathlinks(cls);
			}
			if (name === "SYNO.SDS.TPS.Settings.GeneralPanel") {
				me.patchGeneralSettings(cls);
			}
			return cls;
		};
		Ext.define._tpsHook = true;
	},
	patchSettingsTabPanel: function (Tab) {
		var me = this;
		if (!Tab || !Tab.prototype || Tab.prototype._tpsExtras) { return; }
		Tab.prototype._tpsExtras = true;
		var origInit = Tab.prototype.initComponent;
		if (!origInit) { return; }
		Tab.prototype.initComponent = function () {
			this.enableTabScroll = true;
			this.cls = ((this.cls || "") + " syno-sds-ips-userdefined-tab-panel").replace(/^\s+/, "");
			var ret = origInit.apply(this, arguments);
			if (!this._tpsExtraAdded && this.add) {
				this._tpsExtraAdded = true;
				try { this.add(me.buildFeedsTab()); }
				catch (e) {
					if (window.console && console.error) { console.error("TPS extra tabs", e); }
				}
			}
			return ret;
		};
	},
	telegramNames: ["enable_telegram", "tg_token", "tg_chat_id", "min_interval_telegram", "telegram_follow_mail"],
	patchNotificationTelegram: function (NP) {
		var me = this;
		if (NP.prototype._tpsTelegram) { return; }
		NP.prototype._tpsTelegram = true;
		var origFill = NP.prototype.fillConfig;
		NP.prototype.fillConfig = function (a) {
			var cfg = origFill.apply(this, arguments);
			/* SRM used labelWidth:400 so a long fieldLabel could sit in the
			   label column. DSM 7's content pane is narrower; that leaves a
			   ~400px gap before Email/SMS/Push/Subject inputs. */
			cfg.defaults = Ext.apply({}, cfg.defaults || {});
			cfg.defaults.labelWidth = 180;
			cfg.autoScroll = true;
			cfg.padding = cfg.padding || "0px 12px 0px 0px";
			function fixDisplay(item) {
				if (!item) { return; }
				if (Ext.isArray(item)) { Ext.each(item, fixDisplay); return; }
				if (item.items) { fixDisplay(item.items); }
				if (item.xtype !== "syno_displayfield" && item.xtype !== "displayfield") { return; }
				item.htmlEncode = false;
				if (!item.fieldLabel) { item.hideLabel = true; }
				if (item.fieldLabel && (item.value === undefined || item.value === "")) {
					item.value = item.fieldLabel;
					delete item.fieldLabel;
					item.hideLabel = true;
				}
				if (item.value && String(item.value).indexOf("note-font") !== -1 &&
						String(item.value).indexOf("syno-ux-note") === -1) {
					item.value = String(item.value).replace('class="note-font"', 'class="syno-ux-note note-font"');
				}
			}
			fixDisplay(cfg.items);
			cfg.items = [
				{
					xtype: "syno_fieldset",
					collapsible: false,
					defaults: {labelWidth: 180},
					items: cfg.items || []
				},
				me.telegramFieldset(this)
			];
			return cfg;
		};
		var origActivate = NP.prototype.onActivate;
		NP.prototype.onActivate = function () {
			this._tpsIgnoreDirty = true;
			if (origActivate) { origActivate.apply(this, arguments); }
			me.loadTelegramInto(this);
		};
		var origInit = NP.prototype.initComponent;
		NP.prototype.initComponent = function () {
			var panel = this;
			if (origInit) { origInit.apply(this, arguments); }
			me.hookNotificationApply(this);
			me.hookFormDirtyGate(this);
			this._tpsIgnoreDirty = true;
		};
		var origProc = NP.prototype.processReturnData ||
			(NP.superclass && NP.superclass.processReturnData);
		NP.prototype.processReturnData = function () {
			this._tpsIgnoreDirty = true;
			var ret;
			if (origProc) { ret = origProc.apply(this, arguments); }
			me.loadTelegramInto(this);
			return ret;
		};
		var origLoadSys = NP.prototype.loadSystemNotificationConfig;
		if (origLoadSys) {
			NP.prototype.loadSystemNotificationConfig = function () {
				var panel = this;
				origLoadSys.apply(this, arguments);
				window.setTimeout(function () {
					if (panel.el && panel.el.unmask) { panel.el.unmask(); }
				}, 400);
			};
		}
	},
	telegramFieldset: function (panel) {
		var me = this;
		return {
			xtype: "syno_fieldset",
			title: "Telegram",
			collapsible: false,
			itemId: "tps_telegram_fieldset",
			defaults: {labelWidth: 180},
			items: [
				{xtype: "syno_checkbox", name: "enable_telegram", boxLabel: "Send threat alerts to a Telegram bot", checked: false},
				{xtype: "syno_textfield", name: "tg_token", fieldLabel: "Bot token", inputType: "password", indent: 1, value: ""},
				{xtype: "syno_textfield", name: "tg_chat_id", fieldLabel: "Chat ID", indent: 1, value: ""},
				{xtype: "syno_numberfield", name: "min_interval_telegram", fieldLabel: "Minimum interval (minutes)", indent: 1, maxValue: 60 * 24, allowDecimals: false, minValue: 0, value: 5},
				{xtype: "syno_checkbox", name: "telegram_follow_mail", boxLabel: "Use the same classes as email", indent: 1, checked: true},
				{xtype: "syno_button", itemId: "btn_telegram_test", text: "Send test message", indent: 1, handler: function () { me.testTelegram(panel); }}
			]
		};
	},
	hookNotificationApply: function (panel) {
		var me = this;
		if (!panel || panel._tpsTgHook) { return; }
		panel._tpsTgHook = true;
		var origSend = panel.sendWebAPI;
		if (!origSend) { return; }
		panel.sendWebAPI = function (opts) {
			opts = opts || {};
			var api = (opts.webapi && opts.webapi.api) || opts.api;
			var method = (opts.webapi && opts.webapi.method) || opts.method;
			if (api === "SYNO.TPS.Notification" && method === "set") {
				me.stripTelegramParams(opts);
				me.saveTelegramFrom(panel);
			}
			return origSend.apply(this, arguments);
		};
	},
	stripTelegramParams: function (opts) {
		var me = this;
		function drop(obj) {
			if (!obj) { return; }
			Ext.each(me.telegramNames, function (k) { delete obj[k]; });
		}
		drop(opts.params);
		if (opts.webapi) { drop(opts.webapi.params); }
	},
	telegramFromForm: function (panel) {
		var f = panel && panel.getForm && panel.getForm();
		if (!f) { return {}; }
		function val(name, fallback) {
			var fld = f.findField(name);
			if (!fld || !fld.getValue) { return fallback; }
			return fld.getValue();
		}
		var minutes = Number(val("min_interval_telegram", 5));
		if (!isFinite(minutes) || minutes < 0) { minutes = 5; }
		return {
			enable_telegram: !!val("enable_telegram", false),
			follow_mail: val("telegram_follow_mail", true) !== false,
			min_interval_telegram: Math.round(minutes * 60),
			token: val("tg_token", "") || "",
			chat_id: val("tg_chat_id", "") || ""
		};
	},
	hookFormDirtyGate: function (panel, opts) {
		opts = opts || {};
		var form = panel && panel.getForm && panel.getForm();
		if (!form || form._tpsDirtyGate) { return; }
		form._tpsDirtyGate = true;
		var orig = form.isDirty;
		form.isDirty = function () {
			if (panel._tpsIgnoreDirty) { return false; }
			if (opts.never) { return false; }
			return orig.apply(this, arguments);
		};
	},
	clearTelegramDirty: function (panel) {
		var f = panel && panel.getForm && panel.getForm();
		if (!f) { return; }
		function snap(fld) {
			if (!fld || typeof fld.getValue !== "function") { return; }
			var v = fld.getValue();
			fld.originalValue = v;
			if (fld.startValue !== undefined) { fld.startValue = v; }
			if (fld.wasDirty) { fld.wasDirty = false; }
		}
		Ext.each(this.telegramNames, function (name) {
			snap(f.findField(name));
		});
		panel._tpsIgnoreDirty = false;
	},
	loadTelegramInto: function (panel) {
		var me = this;
		panel._tpsIgnoreDirty = true;
		this.call("SYNO.TPS.Settings.Telegram", "get", 1, {}, function (ok, data) {
			if (panel.el && panel.el.unmask) { panel.el.unmask(); }
			if (!ok || !data) {
				me.clearTelegramDirty(panel);
				return;
			}
			var f = panel.getForm && panel.getForm();
			if (!f) {
				panel._tpsIgnoreDirty = false;
				return;
			}
			function set(name, v) {
				var fld = f.findField(name);
				if (fld && fld.setValue) { fld.setValue(v); }
			}
			set("enable_telegram", !!data.enable_telegram);
			set("telegram_follow_mail", data.follow_mail !== false);
			set("tg_chat_id", data.chat_id || "");
			set("tg_token", "");
			var sec = Number(data.min_interval_telegram);
			if (!isFinite(sec) || sec < 0) { sec = 300; }
			set("min_interval_telegram", Math.round(sec / 60));
			me.clearTelegramDirty(panel);
			window.setTimeout(function () { me.clearTelegramDirty(panel); }, 0);
			window.setTimeout(function () { me.clearTelegramDirty(panel); }, 50);
		});
	},
	saveTelegramFrom: function (panel) {
		var me = this;
		this.call("SYNO.TPS.Settings.Telegram", "set", 1, this.telegramFromForm(panel), function (ok) {
			var f = panel.getForm && panel.getForm();
			var token = f && f.findField("tg_token");
			if (ok && token && token.setValue) { token.setValue(""); }
			me.clearTelegramDirty(panel);
		});
	},
	testTelegram: function (panel) {
		var p = this.telegramFromForm(panel);
		this.call("SYNO.TPS.Settings.Telegram", "test", 1, {token: p.token, chat_id: p.chat_id}, function (ok) {
			var win = panel.findAppWindow && panel.findAppWindow();
			var box = win && win.getMsgBox && win.getMsgBox();
			var msg = ok ? "Telegram test message sent." : "Telegram test failed. Check bot token and chat ID.";
			if (box) { box.alert("", msg); return; }
			if (Ext.Msg) { Ext.Msg.alert("Telegram", msg); }
		});
	},
	buildFeedsTab: function () {
		var me = this;
		var Form = (window.SYNO && SYNO.SDS && SYNO.SDS.Utils && SYNO.SDS.Utils.FormPanel) || Ext.form.FormPanel || Ext.Panel;
		var Grid = (window.SYNO && SYNO.ux && SYNO.ux.GridPanel) || Ext.grid.GridPanel;
		var Modal = (window.SYNO && SYNO.SDS && SYNO.SDS.ModalWindow) || Ext.Window;
		var panel;
		var store = new Ext.data.JsonStore({
			fields: [
				{name: "id"}, {name: "name"}, {name: "url"}, {name: "enabled"}
			]
		});
		function reload() {
			me.call("SYNO.TPS.Settings.Feed", "list", 1, {}, function (ok, data) {
				var rows = [];
				Ext.each((ok && data && data.feeds) || [], function (f) {
					rows.push({
						id: f.id,
						name: f.name,
						url: f.url,
						enabled: !!f.enabled
					});
				});
				store.loadData(rows);
			});
		}
		function selected() {
			return grid.getSelectionModel().getSelected();
		}
		function alertMsg(msg) {
			var win = panel && panel.findAppWindow && panel.findAppWindow();
			var box = win && win.getMsgBox && win.getMsgBox();
			if (box) { box.alert("", msg); return; }
			if (Ext.Msg) { Ext.Msg.alert("", msg); }
		}
		function setButtons() {
			var bar = grid && grid.getTopToolbar && grid.getTopToolbar();
			var rec = selected();
			if (!bar) { return; }
			Ext.each(["feed_edit", "feed_del"], function (id) {
				var btn = bar.getComponent(id);
				if (btn && btn.setDisabled) { btn.setDisabled(!rec); }
			});
		}
		function openEditor(rec) {
			var inner = new Form({
				padding: "12px 20px 0px 12px",
				defaults: {labelWidth: 120},
				items: [
					{xtype: "syno_textfield", name: "feed_name", fieldLabel: "Name", width: 320, value: rec ? rec.get("name") : ""},
					{xtype: "syno_textfield", name: "feed_url", fieldLabel: "HTTPS URL", width: 320, value: rec ? rec.get("url") : ""}
				]
			});
			var win = new Modal({
				owner: panel && panel.findAppWindow && panel.findAppWindow(),
				title: rec ? "Edit Rule Feed" : "Add Rule Feed",
				width: 520,
				height: 220,
				closable: true,
				layout: "fit",
				items: [inner],
				buttons: [
					{xtype: "syno_button", btnStyle: "blue", text: _T("common", "apply") || "Apply", handler: function () {
						var f = inner.getForm && inner.getForm();
						var nameFld = f && f.findField("feed_name");
						var urlFld = f && f.findField("feed_url");
						var name = nameFld && nameFld.getValue ? nameFld.getValue() : "";
						var url = urlFld && urlFld.getValue ? urlFld.getValue() : "";
						function done(ok) {
							if (!ok) {
								alertMsg("Could not save feed. Use HTTPS and a name of letters, digits, ._-");
								return;
							}
							if (win.close) { win.close(); } else if (win.hide) { win.hide(); }
							reload();
						}
						if (rec) {
							me.call("SYNO.TPS.Settings.Feed", "update", 1, {id: rec.get("id"), name: name, url: url}, done);
						} else {
							me.call("SYNO.TPS.Settings.Feed", "add", 1, {name: name, url: url, enabled: true}, done);
						}
					}},
					{xtype: "syno_button", text: _T("common", "close") || "Close", handler: function () {
						if (win.close) { win.close(); } else if (win.hide) { win.hide(); }
					}}
				]
			});
			if (win.open) { win.open(); } else { win.show(); }
		}
		var columns = [];
		var enableCol = null;
		if (window.SYNO && SYNO.ux && SYNO.ux.EnableColumn) {
			enableCol = new SYNO.ux.EnableColumn({
				header: _T("common", "enabled") || "Enabled",
				width: 100,
				dataIndex: "enabled",
				menuDisabled: true,
				sortable: false
			});
			columns.push(enableCol);
		}
		columns.push(
			{header: "Name", dataIndex: "name", width: 160},
			{header: "URL", dataIndex: "url", width: 420, id: "url"}
		);
		var cm = new Ext.grid.ColumnModel({
			defaults: {editable: false, sortable: true, menuDisabled: true, align: "left"},
			columns: columns
		});
		var tbar = [
			{xtype: "syno_button", itemId: "feed_add", text: _T("common", "add") || "Add", handler: function () { openEditor(null); }},
			{xtype: "syno_button", itemId: "feed_edit", text: _T("common", "edit") || "Edit", disabled: true, handler: function () {
				var rec = selected();
				if (rec) { openEditor(rec); }
			}},
			{xtype: "syno_button", itemId: "feed_del", text: _T("common", "delete") || "Delete", disabled: true, handler: function () {
				var rec = selected();
				if (!rec) { return; }
				me.call("SYNO.TPS.Settings.Feed", "delete", 1, {id: rec.get("id")}, function () { reload(); });
			}},
			"->",
			{xtype: "syno_textfilter", iconStyle: "filter", store: store, localFilter: true, localFilterField: ["name", "url"]}
		];
		var sm = new Ext.grid.RowSelectionModel({singleSelect: true, listeners: {selectionchange: setButtons}});
		var gridCfg = {
			flex: 1,
			cls: "device-grid-panel syno-sds-ips-userdefined-panel",
			store: store,
			colModel: cm,
			autoExpandColumn: "url",
			sm: sm,
			tbar: tbar,
			enableHdMenu: false,
			listeners: {
				rowdblclick: function () {
					var rec = selected();
					if (rec) { openEditor(rec); }
				}
			}
		};
		if (enableCol) { gridCfg.plugins = [enableCol]; }
		var grid = new Grid(gridCfg);
		store.on("update", function (s, rec, op) {
			if (!rec || rec.get("id") === undefined) { return; }
			if (op && Ext.data && Ext.data.Record && op !== Ext.data.Record.EDIT) { return; }
			me.call("SYNO.TPS.Settings.Feed", "update", 1, {
				id: rec.get("id"),
				enabled: !!rec.get("enabled")
			}, function () { rec.commit(); });
		});
		panel = new Form({
			title: "Rule Feeds",
			itemId: "SYNO.SDS.TPS.Settings.FeedPanel",
			cls: "syno-sds-ips-settings-device-panel",
			padding: "0px 12px 0px 0px",
			trackResetOnLoad: true,
			useDefaultBtn: false,
			layout: "vbox",
			layoutConfig: {align: "stretch"},
			items: [
				{xtype: "container", layout: "form", autoHeight: true, items: [
					{xtype: "syno_displayfield", hideLabel: true, htmlEncode: false, value: "Extra HTTPS rule feeds are applied on top of ET Open/Pro on General. Run Update Now after changes."}
				]},
				grid
			],
			listeners: {activate: reload}
		});
		me.hookFormDirtyGate(panel, {never: true});
		return panel;
	},
	patchGmapsKey: function () {
		var me = this;
		me._gmapsKey = undefined;
		me.call("SYNO.TPS.Settings.Map", "get", 1, {}, function (ok, data) {
			me._gmapsKey = (ok && data && data.key) ? String(data.key).replace(/\s+/g, "") : "";
			me.applyGmapsKey();
		});
		me.wrapGmapsLoader();
	},
	patchGmapObserver: function () {
		/* Official gmapWarningHidden does d.first() on MutationObserver records.
		   Native MutationRecord lists have length but no Ext .first(). */
		var tries = 0;
		function attach() {
			var P = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Statistic && SYNO.SDS.TPS.Statistic.MapPanel;
			if (!P || !P.prototype) {
				if (tries++ < 40) { window.setTimeout(attach, 100); }
				return;
			}
			if (P.prototype._tpsGmapObs) { return; }
			P.prototype.gmapWarningHidden = function () {
				var Ctor = window.MutationObserver || window.WebKitMutationObserver;
				if (!Ctor || !this.mapContainer || !this.mapContainer.getEl) { return; }
				var el = this.mapContainer.getEl();
				if (!el || !el.dom) { return; }
				var obs = new Ctor(function (records) {
					if (!records || !records.length) { return; }
					var c = records[0] && records[0].target;
					if (c && c.children && c.children.length === 2) {
						c.removeChild(c.children[1]);
					}
				});
				obs.observe(el.dom, { childList: true });
			};
			P.prototype._tpsGmapObs = true;
		}
		attach();
	},
	patchOsmTiles: function () {
		/* Official OSM ImageMapType loads tile.openstreetmap.org. DSM CSP img-src
		   has no OSM host; proxy tiles through same-origin /webman/tps-api. */
		var tries = 0;
		function attach() {
			var P = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Statistic && SYNO.SDS.TPS.Statistic.MapPanel;
			if (!P || !P.prototype || !P.prototype.initMap) {
				if (tries++ < 40) { window.setTimeout(attach, 100); }
				return;
			}
			if (P.prototype._tpsOsm) { return; }
			var orig = P.prototype.initMap;
			P.prototype.initMap = function () {
				orig.apply(this, arguments);
				if (!this.gmap || !window.google || !google.maps || !google.maps.ImageMapType) { return; }
				this.gmap.mapTypes.set("OSM", new google.maps.ImageMapType({
					getTileUrl: function (coord, zoom) {
						var n = Math.pow(2, zoom), x = coord.x, y = coord.y;
						if (y < 0 || y >= n) { return null; }
						if (x < 0 || x >= n) { x = ((x % n) + n) % n; }
						return "/webman/tps-api?api=SYNO.TPS.Settings.Map&method=tile&version=1&z=" +
							zoom + "&x=" + x + "&y=" + y;
					},
					tileSize: new google.maps.Size(256, 256),
					name: "OpenStreetMap",
					maxZoom: 18
				}));
			};
			P.prototype._tpsOsm = true;
		}
		attach();
	},
	patchLogStorage: function () {
		/* Official db_size combo is the only syno_combobox whose store is a raw
		   [['db_size_500mb','500 MB'], …] array. Other combos use SimpleStore
		   {fields:['value','display']}. DSM 7 ComboBox does not map that array
		   onto display/value, so setValue() after get/set clears the field and
		   Apply sends an empty db_size. */
		var tries = 0;
		function sizeKey(v) {
			if (v === 500 || v === "500" || v === "db_size_500mb") { return "db_size_500mb"; }
			if (v === 1024 || v === "1024" || v === "db_size_1gb") { return "db_size_1gb"; }
			if (v === 2048 || v === "2048" || v === "db_size_2gb") { return "db_size_2gb"; }
			return v;
		}
		function sizeStore(helper) {
			function t(sec, key) {
				return (helper && helper.T) ? helper.T(sec, key) : key;
			}
			return new Ext.data.SimpleStore({
				fields: ["value", "display"],
				data: [
					["db_size_500mb", "500 " + t("common", "size_mb")],
					["db_size_1gb", "1 " + t("common", "size_gb")],
					["db_size_2gb", "2 " + t("common", "size_gb")]
				]
			});
		}
		function bindCombo(panel) {
			if (!panel || !panel.getForm) { return; }
			var field = panel.getForm().findField("db_size");
			if (!field) { return; }
			field.displayField = "display";
			field.valueField = "value";
			field.mode = "local";
			field.triggerAction = "all";
			field.forceSelection = true;
			field.editable = false;
			var store = sizeStore(panel.helper);
			if (field.bindStore) { field.bindStore(store); }
			else { field.store = store; }
			var cur = sizeKey((field.getValue && field.getValue()) || field.value);
			if (cur && field.setValue) { field.setValue(cur); }
		}
		function attach() {
			var P = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Settings &&
				SYNO.SDS.TPS.Settings.LogStoragePanel;
			if (!P || !P.prototype || !P.prototype.processReturnData) {
				if (tries++ < 40) { window.setTimeout(attach, 100); }
				return;
			}
			if (P.prototype._tpsStorage) { return; }
			var origFields = P.prototype.getFieldsetStorageUsage;
			if (origFields) {
				P.prototype.getFieldsetStorageUsage = function () {
					var cfg = origFields.apply(this, arguments);
					var self = this;
					Ext.each((cfg && cfg.items) || [], function (item) {
						if (!item || item.name !== "db_size") { return; }
						item.store = sizeStore(self.helper);
						item.mode = "local";
						item.triggerAction = "all";
						item.forceSelection = true;
						item.editable = false;
						item.displayField = "display";
						item.valueField = "value";
					});
					return cfg;
				};
			}
			var origParams = P.prototype.processParams;
			P.prototype.processParams = function (b, a) {
				if (origParams) { origParams.apply(this, arguments); }
				Ext.each(a || [], function (c) {
					if (!c || c.api !== "SYNO.TPS.Settings.Storage" || c.method !== "set") { return; }
					var field = this.getForm() && this.getForm().findField("db_size");
					var v = sizeKey((field && field.getValue && field.getValue()) || (field && field.value));
					c.params = { db_size: v || "db_size_500mb" };
				}, this);
				return a;
			};
			var orig = P.prototype.processReturnData;
			P.prototype.processReturnData = function (d, b) {
				b = b || {};
				var size;
				var cap;
				Ext.each(b.result || [], function (e) {
					if (e && !e.data) { e.data = {}; }
					if (e && e.api === "SYNO.TPS.Settings.Storage" && e.data && e.data.db_size) {
						size = sizeKey(e.data.db_size);
						e.data.db_size = size;
					}
					if (e && e.data && e.data.logStorageMaxLimit === "") {
						delete e.data.logStorageMaxLimit;
					} else if (e && e.data && e.data.logStorageMaxLimit) {
						cap = e.data.logStorageMaxLimit;
					}
				});
				var ret = orig.apply(this, arguments);
				var form = this.getForm && this.getForm();
				var field = form && form.findField("db_size");
				if (field && size && field.setValue) { field.setValue(size); }
				var capField = form && form.findField("logStorageMaxLimit");
				if (capField && cap && capField.setValue) { capField.setValue(cap); }
				return ret;
			};
			P.prototype.getUsbDeviceMaxStorage = function () {
				var panel = this;
				this.sendWebAPI(Ext.apply({
					compound: { stopwhenerror: false, params: this.getWebAPIGetData() },
					callback: function (ok, g) {
						try {
							if (panel.findAppWindow) { panel.findAppWindow().clearStatusBusy(); }
						} catch (e) { /* window already gone */ }
						if (!ok || !g || !g.result) { return; }
						var form = panel.getForm && panel.getForm();
						if (!form) { return; }
						var share = (g.result[0] && g.result[0].data && g.result[0].data.systemdb_shares) || "";
						var devices = (g.result[1] && g.result[1].data && g.result[1].data.devices) || [];
						var i, j, parts, mb, label;
						for (i = 0; i < devices.length; i++) {
							parts = (devices[i] && devices[i].partitions) || [];
							for (j = 0; j < parts.length; j++) {
								if (share && share !== parts[j].share_name) { continue; }
								mb = Number(parts[j].total_size_mb) || 0;
								if (!mb) { continue; }
								label = (mb > 1024)
									? ((mb / 1024).toFixed(2) + " " + panel.helper.T("common", "size_gb"))
									: (mb.toFixed(2) + " " + panel.helper.T("common", "size_mb"));
								form.setValues({ logStorageMaxLimit: label });
								return;
							}
						}
					},
					scope: panel
				}));
			};
			var origAct = P.prototype.onActivate;
			P.prototype.onActivate = function () {
				var ret;
				if (origAct) { ret = origAct.apply(this, arguments); }
				bindCombo(this);
				return ret;
			};
			P.prototype._tpsStorage = true;
		}
		attach();
	},
	patchDeviceCellClick: function () {
		/* Official onCellClick does Ext.DomQuery.select(...).first().
		   DSM 7 DomQuery returns a native array / NodeList, not Ext Collection. */
		var tries = 0;
		function attach() {
			var P = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Overview &&
				SYNO.SDS.TPS.Overview.ConcernedDevicePanel;
			if (!P || !P.prototype) {
				if (tries++ < 40) { window.setTimeout(attach, 100); }
				return;
			}
			if (P.prototype._tpsCellClick) { return; }
			P.prototype.onCellClick = function (grid, row, col, ev) {
				var cell = grid.getView().getCell(row, col);
				var links = (Ext.DomQuery && Ext.DomQuery.select) ? Ext.DomQuery.select("a", cell) : [];
				var node = links && (links[0] || (links.item && links.item(0)));
				if (!node) { return; }
				var wrap = Ext.fly(node);
				if (!wrap || !ev.within(wrap)) { return; }
				var rec = grid.getStore().getAt(row);
				if (rec && rec.data) { this.onShowDetail(rec.data.name); }
			};
			P.prototype._tpsCellClick = true;
		}
		attach();
	},
	applyGmapsKey: function () {
		var key = this._gmapsKey;
		if (!key) { return; }
		var L = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Utils && SYNO.SDS.TPS.Utils.GoogleMapLoader;
		if (!L) { return; }
		var add = function (url) {
			if (!url || String(url).indexOf("key=") !== -1) { return url; }
			return url + (url.indexOf("?") >= 0 ? "&" : "?") + "key=" + encodeURIComponent(key);
		};
		if (L.GMAP_API_URL) { L.GMAP_API_URL = add(L.GMAP_API_URL); }
		if (L.prototype && L.prototype.GMAP_API_URL) {
			L.prototype.GMAP_API_URL = add(L.prototype.GMAP_API_URL);
		}
	},
	wrapGmapsLoader: function () {
		var me = this;
		var tries = 0;
		function attach() {
			var L = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Utils && SYNO.SDS.TPS.Utils.GoogleMapLoader;
			var proto = L && L.prototype;
			if (!proto || !proto.loadScript) {
				if (tries++ < 40) { window.setTimeout(attach, 100); }
				return;
			}
			if (proto.loadScript._tpsGmaps) { return; }
			var orig = proto.loadScript;
			proto.loadScript = function () {
				var self = this;
				var args = arguments;
				function go() {
					me.applyGmapsKey();
					if (me._gmapsKey) {
						var url = self.GMAP_API_URL || (L && L.GMAP_API_URL) || "";
						if (url && url.indexOf("key=") === -1) {
							self.GMAP_API_URL = url + (url.indexOf("?") >= 0 ? "&" : "?") + "key=" + encodeURIComponent(me._gmapsKey);
						} else if (L && L.GMAP_API_URL) {
							self.GMAP_API_URL = L.GMAP_API_URL;
						}
					}
					return orig.apply(self, args);
				}
				if (me._gmapsKey !== undefined) { return go(); }
				me.call("SYNO.TPS.Settings.Map", "get", 1, {}, function (ok, data) {
					me._gmapsKey = (ok && data && data.key) ? String(data.key).replace(/\s+/g, "") : "";
					go();
				});
			};
			proto.loadScript._tpsGmaps = true;
		}
		attach();
	},
	patchMapSeverity: function () {
		var Cls = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Statistic &&
			SYNO.SDS.TPS.Statistic.MapPanel;
		if (!Cls || !Cls.prototype || Cls.prototype._tpsSev) { return; }
		Cls.prototype.onSeverityAfterrender = function () {
			var self = this;
			Ext.each(["high", "medium", "low"], function (name) {
				var rec = self.icons && self.icons[name];
				var el = rec && document.getElementById(rec.id);
				if (!el) { return; }
				el.onclick = function () {
					var on = !self.getSeverityChecked(this.id);
					self.setSeverityChecked(this.id, on);
					if (on) { this.classList.remove("unchecked"); }
					else { this.classList.add("unchecked"); }
				};
			});
		};
		Cls.prototype.resetSeverityIcons = function () {
			var name, el;
			for (name in this.icons) {
				if (!this.icons.hasOwnProperty(name)) { continue; }
				el = document.getElementById(this.icons[name].id);
				if (!el) { continue; }
				if (this.icons[name].checked === false) { el.classList.remove("unchecked"); }
				this.icons[name].checked = true;
			}
			if (this.store && this.store.clearFilter) { this.store.clearFilter(); }
		};
		Cls.prototype._tpsSev = true;
	},
	hookPolling: function () {
		var me = this;
		if (!window.SYNO || !SYNO.API || !SYNO.API.Request) { return; }
		var Polling = SYNO.API.Request.Polling;
		if (!Polling) {
			Polling = SYNO.API.Request.Polling = {};
		}
		if (Polling._tpsBridge) { return; }
		var origList = Polling.List;
		var origReg = Polling.Register;
		var origUnreg = Polling.Unregister;
		Polling.List = function (opts) {
			opts = opts || {};
			if (opts.task_id_prefix && String(opts.task_id_prefix).indexOf("SYNO.TPS") === 0) {
				var ids = [];
				var updater = SYNO.SDS.TPS.Utils && SYNO.SDS.TPS.Utils.SignatureUpdater;
				if (updater && updater.taskId) { ids.push(updater.taskId); }
				if (opts.callback) {
					opts.callback.call(opts.scope || window, true, me.adminList(ids));
				}
				return;
			}
			if (origList) { return origList.apply(this, arguments); }
			if (opts.callback) {
				opts.callback.call(opts.scope || window, true, me.adminList([]));
			}
		};
		Polling.Register = function (opts) {
			var api = opts && opts.webapi && opts.webapi.api;
			if (me.isTps(api)) {
				var self = (opts && opts.scope) || window;
				var tick = function () {
					me.call(
						opts.webapi.api,
						opts.webapi.method,
						opts.webapi.version,
						(opts.webapi.params) || {},
						opts.status_callback || opts.callback,
						self
					);
				};
				if (!opts || opts.immediate !== false) { tick(); }
				return window.setInterval(tick, ((opts && opts.interval) || 5) * 1000);
			}
			if (origReg) { return origReg.apply(this, arguments); }
			return 0;
		};
		Polling.Unregister = function (id) {
			if (typeof id === "number") {
				window.clearInterval(id);
				return;
			}
			if (origUnreg) {
				try { return origUnreg.apply(this, arguments); } catch (e) { return; }
			}
		};
		Polling._tpsBridge = true;
	},
	pickApi: function (opts) {
		var p = (opts && (opts.params || opts.jsonData)) || {};
		return p.api || (opts && opts.api) || "";
	},
	install: function () {
		var me = this;
		if (me._installed) {
			me.injectInfo();
			me.injectModuleListCss();
			me.hookManagerRequest();
			return;
		}
		me.injectInfo();
		me.injectModuleListCss();
		me.hookManagerRequest();
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
		if (Ext.Component) { hookProto(Ext.Component, "sendWebAPI"); }
		hookProto(SYNO.SDS.AppWindow, "downloadWebAPI", function (opts, orig, args) {
			var api = opts && (opts.api || (opts.webapi && opts.webapi.api));
			if (me.isTps(api)) { return me.download(opts); }
			return orig.apply(this, args);
		});
		function wrapPollReg(cls) {
			if (!cls || !cls.prototype || !cls.prototype.pollReg || cls.prototype.pollReg._tpsBridge) { return; }
			var origPoll = cls.prototype.pollReg;
			var origUnreg = cls.prototype.pollUnreg;
			cls.prototype.pollReg = function (opts) {
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
			cls.prototype.pollReg._tpsBridge = true;
			if (origUnreg && !origUnreg._tpsBridge) {
				cls.prototype.pollUnreg = function (id) {
					if (typeof id === "number") {
						window.clearInterval(id);
						return;
					}
					if (id) { window.clearInterval(id); }
					try { return origUnreg.apply(this, arguments); } catch (e) { return; }
				};
				cls.prototype.pollUnreg._tpsBridge = true;
			}
		}
		wrapPollReg(SYNO.SDS.AppWindow);
		wrapPollReg(Ext.Component);
		if (window.SYNO && SYNO.API && SYNO.API.Store && SYNO.API.Store.prototype && SYNO.API.Store.prototype.load && !SYNO.API.Store.prototype.load._tpsBridge) {
			var origStoreLoad = SYNO.API.Store.prototype.load;
			SYNO.API.Store.prototype.load = function (options) {
				if (!me.isTps(this.api)) {
					return origStoreLoad.apply(this, arguments);
				}
				var self = this;
				var params = Ext.apply({}, this.baseParams || {}, (options && options.params) || {});
				me.call(this.api, this.method, this.version || 1, params, function (ok, data, raw) {
					var env = me.envelope(raw || { success: ok, data: data });
					var fake = { responseText: Ext.encode(env), status: ok ? 200 : 500 };
					if (ok && self.reader && self.loadRecords) {
						try {
							var recs = self.reader.read(fake);
							self.loadRecords(recs, options || {}, true);
							if (options && options.callback) {
								options.callback.call(options.scope || self, recs, options, true);
							}
							return;
						} catch (e) {
							if (self.loadData && data) {
								self.loadData(data);
								return;
							}
						}
					}
					if (!ok && self.fireEvent) {
						self.fireEvent("loadexception", self, fake, options);
					}
				});
			};
			SYNO.API.Store.prototype.load._tpsBridge = true;
		}
		if (window.SYNO && SYNO.API && SYNO.API.Request && !SYNO.API.Request._tpsBridge) {
			var origReq = SYNO.API.Request;
			var wrappedReq = function (opts) {
				var args = arguments;
				if (opts && opts.compound && opts.compound.params) {
					return me.dispatch(opts, function () { return origReq.apply(this, args); });
				}
				if (opts && me.isHosted(opts.api)) {
					return me.dispatch(opts, function () { return origReq.apply(this, args); });
				}
				return origReq.apply(this, args);
			};
			var k;
			for (k in origReq) {
				if (Object.prototype.hasOwnProperty.call(origReq, k)) {
					wrappedReq[k] = origReq[k];
				}
			}
			wrappedReq.Polling = origReq.Polling;
			wrappedReq._tpsBridge = true;
			SYNO.API.Request = wrappedReq;
		}
		me.hookExtDefine();
		me.patchDisplayHtml();
		me.patchPercentLabels();
		me.patchMapSeverity();
		me.patchGmapsKey();
		me.patchGmapObserver();
		me.patchOsmTiles();
		me.patchDeviceCellClick();
		me.patchLogStorage();
		me.patchOverviewPathlinks();
		me.patchGeneralSettings();
		me.injectSettingsTabs();
		me.hookPolling();
		if (Ext.Ajax && Ext.Ajax.request && !Ext.Ajax.request._tpsBridge) {
			var origAjax = Ext.Ajax.request;
			Ext.Ajax.request = function (opts) {
				opts = opts || {};
				if (opts._tpsDirect) { return origAjax.apply(this, arguments); }
				var api = me.pickApi(opts);
				if (!me.isHosted(api)) { return origAjax.apply(this, arguments); }
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
