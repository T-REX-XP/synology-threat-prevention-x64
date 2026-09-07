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
			left -= 1;
			if (!left && opts.callback) {
				opts.callback.call(opts.scope || window, true, { result: out, has_fail: failed });
			}
		}
		Ext.each(items, function (item, idx) {
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
	looksOfficialHtml: function (v) {
		return typeof v === "string" && v.indexOf("<") !== -1 &&
			(v.indexOf("pathlink") !== -1 || v.indexOf("<font") !== -1 ||
				v.indexOf("<a ") !== -1 || v.indexOf("<a>") !== -1 ||
				v.indexOf("font-order") !== -1 ||
				v.indexOf("syno-sds-ips-event-") !== -1 ||
				v.indexOf('class="syno-sds-ips') !== -1);
	},
	restoreOfficialLabel: function (field) {
		var html = field && field.fieldLabel;
		if (!this.looksOfficialHtml(html)) { return; }
		var sep = field.labelSeparator;
		if (sep === undefined || sep === null) { sep = ""; }
		var markup = html + sep;
		var el = field.labelEl;
		if (!el && field.el && field.el.down) {
			el = field.el.down("label.x-form-item-label") ||
				field.el.down(".x-form-item-label") ||
				field.el.down("label");
		}
		if (!el && field.itemCt && field.itemCt.down) {
			el = field.itemCt.down("label.x-form-item-label") ||
				field.itemCt.down(".x-form-item-label") ||
				field.itemCt.down("label");
		}
		if (!el && field.el && field.el.up) {
			var item = field.el.up(".x-form-item");
			el = item && item.down && (item.down("label.x-form-item-label") ||
				item.down(".x-form-item-label") || item.down("label"));
		}
		if (el && el.dom) { el.dom.innerHTML = markup; }
	},
	patchDisplayHtml: function () {
		/* Official Overview injects <a class="pathlink"> into syno_displayfield.
		   SRM rendered that HTML. DSM 7 encodes it, so the link is visible as
		   text and afterrender does b.el.down("a").on(...) on null.
		   Statistics TopNPercentPanel puts <font class="font-order"> in
		   fieldLabel (not value); DSM 7 encodes that too. */
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
				if (me.looksOfficialHtml(this.fieldLabel || label)) {
					this.on("afterrender", function () {
						me.restoreOfficialLabel(field);
						window.setTimeout(function () { me.restoreOfficialLabel(field); }, 0);
					}, this);
				}
			};
			var origSet = proto.setValue;
			proto.setValue = function (v) {
				if (me.looksOfficialHtml(v)) { this.htmlEncode = false; }
				if (origSet) { return origSet.apply(this, arguments); }
				this.value = v;
				if (this.rendered && this.el) { this.el.update(this.htmlEncode ? Ext.util.Format.htmlEncode(v) : v); }
			};
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
				me.restoreOfficialLabel(this);
				window.setTimeout(function () { me.restoreOfficialLabel(field); }, 0);
			};
			Cls.prototype._tpsPctLabel = true;
		}
		attach();
	},
	injectSettingsTabs: function () {
		var me = this;
		var tries = 0;
		function attach() {
			var Tab = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Settings && SYNO.SDS.TPS.Settings.TabPanel;
			if (!Tab || !Tab.prototype) {
				if (tries++ < 40) { window.setTimeout(attach, 100); }
				return;
			}
			if (Tab.prototype._tpsExtras) { return; }
			Tab.prototype._tpsExtras = true;
			var origInit = Tab.prototype.initComponent;
			var origCtor = Tab.prototype.constructor;
			function after(panel) {
				if (!panel || !panel.on) { return; }
				panel.on("afterrender", function () {
					if (panel._tpsExtraAdded || !panel.add) { return; }
					panel._tpsExtraAdded = true;
					try {
						panel.add(me.buildTelegramTab(), me.buildFeedsTab());
						if (panel.doLayout) { panel.doLayout(); }
					} catch (e) {
						if (window.console && console.error) { console.error("TPS extra tabs", e); }
					}
				}, panel, {single: true});
			}
			if (origInit) {
				Tab.prototype.initComponent = function () {
					var ret = origInit.apply(this, arguments);
					after(this);
					return ret;
				};
			} else if (origCtor) {
				Tab.prototype.constructor = function () {
					var ret = origCtor.apply(this, arguments);
					after(this);
					return ret;
				};
			}
		}
		attach();
	},
	buildTelegramTab: function () {
		var me = this;
		var Check = Ext.form.Checkbox;
		var Text = Ext.form.TextField;
		var NumberField = Ext.form.NumberField;
		var Panel = Ext.form.FormPanel || Ext.Panel;
		var enable = new Check({boxLabel: "Enable Telegram alerts", name: "enable_telegram"});
		var token = new Text({
			fieldLabel: "Bot token",
			name: "token",
			inputType: "password",
			width: 360,
			emptyText: "leave blank to keep saved token"
		});
		var chat = new Text({fieldLabel: "Chat ID", name: "chat_id", width: 220});
		var interval = new NumberField({
			fieldLabel: "Min interval (sec)",
			name: "min_interval_telegram",
			value: 300,
			width: 80,
			allowDecimals: false,
			minValue: 0
		});
		var follow = new Check({boxLabel: "Use same classes as email", name: "follow_mail", checked: true});
		function load() {
			me.call("SYNO.TPS.Settings.Telegram", "get", 1, {}, function (ok, data) {
				if (!ok || !data) { return; }
				enable.setValue(!!data.enable_telegram);
				follow.setValue(data.follow_mail !== false);
				if (interval.setValue) { interval.setValue(data.min_interval_telegram || 300); }
				chat.setValue(data.chat_id || "");
				token.setValue("");
			});
		}
		var saveBtn = new Ext.Button({
			text: "Apply",
			handler: function () {
				me.call("SYNO.TPS.Settings.Telegram", "set", 1, {
					enable_telegram: enable.getValue(),
					follow_mail: follow.getValue(),
					min_interval_telegram: interval.getValue(),
					token: token.getValue(),
					chat_id: chat.getValue()
				}, function (ok) {
					if (ok) { token.setValue(""); load(); }
					else if (Ext.Msg) { Ext.Msg.alert("Telegram", "Save failed"); }
				});
			}
		});
		var testBtn = new Ext.Button({
			text: "Test",
			handler: function () {
				me.call("SYNO.TPS.Settings.Telegram", "test", 1, {
					token: token.getValue(),
					chat_id: chat.getValue()
				}, function (ok) {
					if (Ext.Msg) {
						Ext.Msg.alert("Telegram", ok ? "Test message sent." : "Test failed. Check token and chat ID.");
					}
				});
			}
		});
		return new Panel({
			title: "Telegram",
			itemId: "SYNO.SDS.TPS.Settings.TelegramPanel",
			padding: 12,
			autoScroll: true,
			border: false,
			items: [
				{xtype: "label", html: "<p>Send alerts to a Telegram bot. Token stays in etc/telegram.conf (not in the package).</p>"},
				enable, token, chat, interval, follow,
				{xtype: "container", layout: "column", items: [saveBtn, {xtype: "box", width: 12}, testBtn]}
			],
			listeners: {activate: load}
		});
	},
	buildFeedsTab: function () {
		var me = this;
		var Panel = Ext.form.FormPanel || Ext.Panel;
		var store = new Ext.data.SimpleStore({
			fields: ["id", "name", "url", "enabled"]
		});
		function reload() {
			me.call("SYNO.TPS.Settings.Feed", "list", 1, {}, function (ok, data) {
				var rows = [];
				Ext.each((ok && data && data.feeds) || [], function (f) {
					rows.push([f.id, f.name, f.url, f.enabled ? "yes" : "no"]);
				});
				store.loadData(rows);
			});
		}
		var nameF = new Ext.form.TextField({fieldLabel: "Name", width: 160, emptyText: "letters, digits, ._-"});
		var urlF = new Ext.form.TextField({fieldLabel: "HTTPS URL", width: 400});
		var grid = new Ext.grid.GridPanel({
			store: store,
			height: 200,
			autoExpandColumn: "url",
			columns: [
				{header: "Name", dataIndex: "name", width: 140},
				{header: "URL", dataIndex: "url", width: 360, id: "url"},
				{header: "On", dataIndex: "enabled", width: 50}
			],
			sm: new Ext.grid.RowSelectionModel({singleSelect: true})
		});
		function selectedId() {
			var rec = grid.getSelectionModel().getSelected();
			return rec ? rec.get("id") : 0;
		}
		var addBtn = new Ext.Button({
			text: "Add",
			handler: function () {
				me.call("SYNO.TPS.Settings.Feed", "add", 1, {
					name: nameF.getValue(),
					url: urlF.getValue(),
					enabled: true
				}, function (ok) {
					if (!ok && Ext.Msg) { Ext.Msg.alert("Feeds", "Add failed. Use https and a simple name."); }
					reload();
				});
			}
		});
		var toggleBtn = new Ext.Button({
			text: "Enable / disable",
			handler: function () {
				var rec = grid.getSelectionModel().getSelected();
				if (!rec) { return; }
				me.call("SYNO.TPS.Settings.Feed", "update", 1, {
					id: rec.get("id"),
					enabled: rec.get("enabled") !== "yes"
				}, function () { reload(); });
			}
		});
		var delBtn = new Ext.Button({
			text: "Remove",
			handler: function () {
				var id = selectedId();
				if (!id) { return; }
				me.call("SYNO.TPS.Settings.Feed", "delete", 1, {id: id}, function () { reload(); });
			}
		});
		return new Panel({
			title: "Rule feeds",
			itemId: "SYNO.SDS.TPS.Settings.FeedPanel",
			padding: 12,
			autoScroll: true,
			border: false,
			items: [
				{xtype: "label", html: "<p>Extra rule URLs are added on top of ET Open/Pro (General tab). Apply Update Now after changes.</p>"},
				grid, nameF, urlF,
				{xtype: "container", layout: "column", items: [addBtn, {xtype: "box", width: 12}, toggleBtn, {xtype: "box", width: 12}, delBtn]}
			],
			listeners: {activate: reload}
		});
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
		me.patchDisplayHtml();
		me.patchPercentLabels();
		me.patchMapSeverity();
		me.patchGmapsKey();
		me.patchGmapObserver();
		me.patchDeviceCellClick();
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
