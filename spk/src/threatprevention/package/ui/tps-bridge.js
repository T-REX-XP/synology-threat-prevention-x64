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
	adminList: function (ids) {
		var admin = ids || [];
		admin.size = function () { return this.length; };
		return { admin: admin };
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
		if (Ext.Component) { hookProto(Ext.Component, "sendWebAPI"); }
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
					if (typeof id === "number") {
						window.clearInterval(id);
						return;
					}
					if (id) { window.clearInterval(id); }
					try { return origUnreg.apply(this, arguments); } catch (e) { return; }
				};
				SYNO.SDS.AppWindow.prototype.pollUnreg._tpsBridge = true;
			}
		}
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
				if (opts && me.isTps(opts.api)) {
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
		me.hookPolling();
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
