/* Community ExtJS desktop app. Original code — not Synology synoips.js. */
Ext.namespace("SYNO.SDS.ThreatPrevention");

SYNO.SDS.ThreatPrevention.api = function (api, method, params, cb, err) {
	var host = window.location.hostname || "127.0.0.1";
	var url = "http://" + host + ":19557/";
	Ext.Ajax.request({
		url: url,
		method: "GET",
		params: Ext.apply({ api: api, method: method, version: 1 }, params || {}),
		success: function (resp) {
			var j;
			try { j = Ext.decode(resp.responseText); } catch (e) { j = { success: false }; }
			if (j && j.success) {
				if (cb) { cb(j.data || {}); }
			} else if (err) {
				err(j);
			}
		},
		failure: function () {
			if (err) { err({ error: { code: 500 } }); }
		}
	});
};

Ext.define("SYNO.SDS.ThreatPrevention.Application", {
	extend: "SYNO.SDS.AppInstance",
	appWindowName: "SYNO.SDS.ThreatPrevention.MainWindow",
	constructor: function () {
		this.callParent(arguments);
	}
});

Ext.define("SYNO.SDS.ThreatPrevention.MainWindow", {
	extend: "SYNO.SDS.AppWindow",
	constructor: function (cfg) {
		this.appInstance = cfg.appInstance;
		this._stores = this._buildStores();
		this._tabs = this._buildTabs();
		SYNO.SDS.ThreatPrevention.MainWindow.superclass.constructor.call(this, Ext.apply({
			width: 1100,
			height: 720,
			minWidth: 800,
			minHeight: 520,
			resizable: true,
			maximizable: true,
			minimizable: true,
			layout: "fit",
			cls: "syno-app-win",
			items: [this._tabs]
		}, cfg));
		this.on("afterrender", this._reloadAll, this);
	},
	onOpen: function () {
		SYNO.SDS.ThreatPrevention.MainWindow.superclass.onOpen.apply(this, arguments);
		this._reloadAll();
	},
	onClose: function () {
		SYNO.SDS.ThreatPrevention.MainWindow.superclass.onClose.apply(this, arguments);
		this.doClose();
		return true;
	},
	_buildStores: function () {
		return {
			events: new Ext.data.JsonStore({
				fields: ["timestamp", "severity", "sig_name", "ip_src_str", "port_src", "ip_dst_str", "port_dst", "action", "cid", "sig_sid", "sig_class_name"],
				data: []
			}),
			classes: new Ext.data.JsonStore({
				fields: ["sig_class_id", "name", "description", "total", "action"],
				data: []
			}),
			rules: new Ext.data.JsonStore({
				fields: ["sig_sid", "sig_name", "class_name", "action", "sig_class_id"],
				data: []
			}),
			devices: new Ext.data.JsonStore({
				fields: ["device_name", "mac", "online", "detect", "count", "ip"],
				data: []
			}),
			topClass: new Ext.data.JsonStore({ fields: ["name", "count"], data: [] }),
			topSrc: new Ext.data.JsonStore({ fields: ["ip", "count"], data: [] })
		};
	},
	_buildTabs: function () {
		var me = this;
		this._ovStatus = new Ext.Panel({
			border: false,
			bodyStyle: "padding:12px",
			html: "<p>Loading status…</p>"
		});
		this._evDetail = new Ext.Panel({
			title: "Event Details",
			height: 180,
			autoScroll: true,
			bodyStyle: "padding:8px",
			html: "<p>Select an event to view details.</p>"
		});
		var evGrid = new Ext.grid.GridPanel({
			store: me._stores.events,
			flex: 1,
			columns: [
				{ header: "Time", dataIndex: "timestamp", width: 140 },
				{ header: "Severity", dataIndex: "severity", width: 70 },
				{ header: "Signature", dataIndex: "sig_name", width: 320 },
				{ header: "Source", dataIndex: "ip_src_str", width: 130 },
				{ header: "Destination", dataIndex: "ip_dst_str", width: 130 },
				{ header: "Action", dataIndex: "action", width: 70 }
			],
			sm: new Ext.grid.RowSelectionModel({ singleSelect: true }),
			listeners: {
				rowclick: function (g, i) {
					var rec = g.getStore().getAt(i);
					if (!rec) { return; }
					SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Event", "get", { cid: rec.get("cid") }, function (e) {
						me._evDetail.update(
							"<b>" + Ext.util.Format.htmlEncode(e.sig_name || "") + "</b> (sid " + e.sig_sid + ")<br>" +
							"Class: " + Ext.util.Format.htmlEncode(e.sig_class_name || "") + "<br>" +
							Ext.util.Format.htmlEncode(e.ip_src_str) + ":" + e.port_src + " → " +
							Ext.util.Format.htmlEncode(e.ip_dst_str) + ":" + e.port_dst +
							(e.data_payload ? "<pre>" + Ext.util.Format.htmlEncode(e.data_payload) + "</pre>" : "")
						);
					});
				}
			}
		});
		this._evQ = new Ext.form.TextField({ emptyText: "Find signature or IP", width: 200 });
		var classGrid = new Ext.grid.EditorGridPanel({
			store: me._stores.classes,
			title: "Class Policy",
			flex: 1,
			clicksToEdit: 1,
			columns: [
				{ header: "Class", dataIndex: "name", width: 180 },
				{ header: "Description", dataIndex: "description", width: 280 },
				{ header: "Rules", dataIndex: "total", width: 60 },
				{
					header: "Action", dataIndex: "action", width: 90,
					editor: new Ext.form.ComboBox({
						store: ["alert", "drop", "pass", "disable"],
						triggerAction: "all",
						editable: false
					})
				}
			],
			listeners: {
				afteredit: function (e) {
					SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Signature.Policy", "set", {
						type: "class",
						sig_class_id: e.record.get("sig_class_id"),
						action: e.value
					});
				}
			}
		});
		var ruleGrid = new Ext.grid.EditorGridPanel({
			store: me._stores.rules,
			title: "Signature Rules",
			flex: 1,
			clicksToEdit: 1,
			columns: [
				{ header: "SID", dataIndex: "sig_sid", width: 80 },
				{ header: "Signature", dataIndex: "sig_name", width: 360 },
				{ header: "Class", dataIndex: "class_name", width: 140 },
				{
					header: "Action", dataIndex: "action", width: 90,
					editor: new Ext.form.ComboBox({
						store: ["alert", "drop", "pass", "disable"],
						triggerAction: "all",
						editable: false
					})
				}
			],
			listeners: {
				afteredit: function (e) {
					SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Signature.Policy", "set", {
						type: "signature",
						raw_sid: e.record.get("sig_sid"),
						sig_class_id: e.record.get("sig_class_id"),
						sig_name: e.record.get("sig_name"),
						action: e.value
					});
				}
			}
		});
		this._stHtml = new Ext.Panel({ border: false, bodyStyle: "padding:12px", html: "" });
		this._setForm = new Ext.form.FormPanel({
			labelWidth: 160,
			bodyStyle: "padding:12px",
			defaults: { anchor: "90%" },
			items: [
				{ xtype: "checkbox", name: "enable_sensor", fieldLabel: "Enable Threat Prevention" },
				{ xtype: "checkbox", name: "enable_prevention", fieldLabel: "Drop detected packets (stored; NFQUEUE not wired)" },
				{ xtype: "textfield", name: "interface_list", fieldLabel: "Monitored interface" },
				{
					xtype: "combo", name: "network_security_mode", fieldLabel: "When busy",
					store: [["availability", "Network stability priority"], ["security", "Security priority"]],
					mode: "local", triggerAction: "all", editable: false
				},
				{ xtype: "checkbox", name: "auto_update", fieldLabel: "Automatically update signatures" },
				{
					xtype: "combo", name: "source", fieldLabel: "Update source",
					store: [["et-open", "ET Open"], ["et-pro", "ET Pro"]],
					mode: "local", triggerAction: "all", editable: false
				},
				{ xtype: "textfield", name: "code", fieldLabel: "ET Pro code" },
				{
					xtype: "combo", name: "limit", fieldLabel: "Maximum log usage",
					store: [[500, "500 MiB"], [1024, "1 GiB"], [2048, "2 GiB"]],
					mode: "local", triggerAction: "all", editable: false
				},
				{ xtype: "checkbox", name: "enable_notification", fieldLabel: "Enable event notification" },
				{ xtype: "textfield", name: "subject_prefix", fieldLabel: "Subject prefix" }
			],
			buttons: [
				{
					text: "Save",
					handler: function () { me._saveSettings(); }
				},
				{
					text: "Update Now",
					handler: function () {
						SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Settings.Update", "start_update", {}, function () {
							Ext.Msg.alert("Threat Prevention", "Signature update started.");
						});
					}
				},
				{
					text: "Clear Logs",
					handler: function () {
						Ext.Msg.confirm("Threat Prevention", "Clear all logged events?", function (btn) {
							if (btn === "yes") {
								SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Settings.Storage", "clear_log", {}, function () {
									me._reloadAll();
								});
							}
						});
					}
				}
			]
		});
		return new Ext.TabPanel({
			activeTab: 0,
			plain: true,
			items: [
				{
					title: "Overview",
					layout: "fit",
					items: [this._ovStatus],
					listeners: { activate: function () { me._loadOverview(); } }
				},
				{
					title: "Events",
					layout: { type: "vbox", align: "stretch" },
					tbar: [
						this._evQ,
						{
							text: "Find",
							handler: function () { me._loadEvents(); }
						}
					],
					items: [evGrid, this._evDetail],
					listeners: { activate: function () { me._loadEvents(); } }
				},
				{
					title: "Self-Defined Policy",
					layout: { type: "vbox", align: "stretch" },
					items: [classGrid, ruleGrid],
					listeners: { activate: function () { me._loadPolicy(); } }
				},
				{
					title: "Statistics",
					layout: "fit",
					items: [this._stHtml],
					listeners: { activate: function () { me._loadStats(); } }
				},
				{
					title: "Settings",
					layout: "fit",
					items: [this._setForm],
					listeners: { activate: function () { me._loadSettings(); } }
				}
			]
		});
	},
	_reloadAll: function () {
		this._loadOverview();
		this._loadEvents();
		this._loadPolicy();
		this._loadStats();
		this._loadSettings();
	},
	_loadOverview: function () {
		var me = this;
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Overview", "get", {}, function (o) {
			var s = o.sensor || {};
			var st = o.stats || {};
			me._ovStatus.update(
				"<h3>System " + (s.status === "running" ? "Well Protected" : "Service Stopped") + "</h3>" +
				"<p>Engine: <b>" + Ext.util.Format.htmlEncode(s.status || "") + "</b> (pid " + (s.pid || "?") + ")</p>" +
				"<p>Capture interface: <code>" + Ext.util.Format.htmlEncode(s.interface_list || "auto") + "</code></p>" +
				"<p>Rules: " + Ext.util.Format.htmlEncode(o.rules || "") + "</p>" +
				"<p>Last update: " + Ext.util.Format.htmlEncode(o.last_updated || "not yet") + "</p>" +
				"<p>Malicious events (past 7 days): <b>" + (st.total || 0) + "</b> · High " + (st.high || 0) +
				" · Medium " + (st.medium || 0) + " · Low " + (st.low || 0) + "</p>" +
				"<p class='x-muted'>Community ExtJS app — not official synoips.js. API: SYNO.TPS.* via tpsweb :19557</p>"
			);
		}, function () {
			me._ovStatus.update("<p>Cannot reach tpsweb on port 19557. Start the package, or use HTTP DSM (mixed content blocks HTTPS→HTTP).</p>");
		});
	},
	_loadEvents: function () {
		var me = this;
		var q = this._evQ ? this._evQ.getValue() : "";
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Event", "list", {
			limit: 80,
			date_range: "7days",
			key_words: q
		}, function (d) {
			me._stores.events.loadData(d.events || []);
		});
	},
	_loadPolicy: function () {
		var me = this;
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Signature", "list", {}, function (d) {
			me._stores.classes.loadData(d.classes || []);
		});
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Signature.Rule", "list", { limit: 80 }, function (d) {
			me._stores.rules.loadData(d.rules || []);
		});
	},
	_loadStats: function () {
		var me = this;
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Event.Statistic", "get", { date_range: "7days" }, function (s) {
			var cls = (s.top_class || []).map(function (c) {
				return "<tr><td>" + Ext.util.Format.htmlEncode(c.name) + "</td><td>" + c.count + "</td></tr>";
			}).join("");
			var src = (s.top_src || []).map(function (c) {
				return "<tr><td>" + Ext.util.Format.htmlEncode(c.ip) + "</td><td>" + c.count + "</td></tr>";
			}).join("");
			me._stHtml.update(
				"<p>Total " + s.total + " · High " + s.high + " · Medium " + s.medium + " · Low " + s.low + "</p>" +
				"<h4>Top event types</h4><table>" + (cls || "<tr><td>No data</td></tr>") + "</table>" +
				"<h4>Top source IPs</h4><table>" + (src || "<tr><td>No data</td></tr>") + "</table>"
			);
		});
	},
	_loadSettings: function () {
		var me = this;
		var form = me._setForm.getForm();
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Sensor", "get", {}, function (s) {
			form.setValues(s);
		});
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Settings.Update.Schedule", "get", {}, function (s) {
			form.setValues(s);
		});
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Settings.Update.Source", "get", {}, function (s) {
			form.setValues(s);
		});
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Settings.Storage", "get", {}, function (s) {
			form.setValues(s);
		});
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Notification", "get", {}, function (s) {
			form.setValues(s);
		});
	},
	_saveSettings: function () {
		var v = this._setForm.getForm().getValues();
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Sensor", "set", {
			enable_sensor: !!v.enable_sensor,
			enable_prevention: !!v.enable_prevention,
			interface_list: v.interface_list || "",
			network_security_mode: v.network_security_mode || "availability"
		});
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Settings.Update.Schedule", "set", { auto_update: !!v.auto_update });
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Settings.Update.Source", "set", { source: v.source || "et-open", code: v.code || "" });
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Settings.Storage", "set", { limit: v.limit || 500 });
		SYNO.SDS.ThreatPrevention.api("SYNO.TPS.Notification", "set", {
			enable_notification: !!v.enable_notification,
			subject_prefix: v.subject_prefix || ""
		});
		Ext.Msg.alert("Threat Prevention", "Settings saved. Restart the package if the capture interface changed.");
	}
});
