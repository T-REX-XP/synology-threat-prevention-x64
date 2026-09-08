/* Pack-time part 3/3 — Settings inject (capture mode, IDS chrome, Telegram, feeds). */
window.SYNO = window.SYNO || {};
SYNO.SDS = SYNO.SDS || {};
SYNO.SDS.TPS = SYNO.SDS.TPS || {};
if (window.Ext && Ext.namespace) {
	Ext.namespace("SYNO.SDS.TPS");
}
SYNO.SDS.TPS.Bridge = SYNO.SDS.TPS.Bridge || {};
(function (B) {
	var extra = {
		findNamed: function (root, name) {
			if (!root || !name) { return null; }
			var form = root.getForm && root.getForm();
			var f = form && form.findField && form.findField(name);
			if (f && (f.name === name || f.hiddenName === name || f.itemId === name)) {
				return f;
			}
			if (root.findBy) {
				var list = root.findBy(function (c) {
					return c && (c.name === name || c.hiddenName === name || c.itemId === name);
				});
				if (list && list.length) { return list[0]; }
			}
			return f || null;
		},
		timeItemStore: function (kind) {
			var max = kind === "hour" ? 24 : 60;
			var data = [];
			var i;
			for (i = 0; i < max; i++) {
				data.push([i, (i < 10 ? "0" : "") + i]);
			}
			return new Ext.data.SimpleStore({ fields: ["value", "display"], data: data });
		},
		registerScheduleFields: function (panel) {
			var form = panel && panel.getForm && panel.getForm();
			if (!form || !form.add) { return; }
			var me = this;
			Ext.each(["weekday", "hour", "minute"], function (name) {
				var existing = form.findField && form.findField(name);
				if (existing && (existing.name === name || existing.hiddenName === name)) { return; }
				var fld = me.findNamed(panel, name);
				if (fld) { form.add(fld); }
			});
		},
		bindTimeCombos: function (panel) {
			var me = this;
			Ext.each(["hour", "minute"], function (name) {
				var field = me.findNamed(panel, name);
				if (!field || field._tpsTimeBound) { return; }
				field.mode = "local";
				field.triggerAction = "all";
				field.forceSelection = true;
				field.editable = false;
				var store = me.timeItemStore(name);
				if (field.bindStore) { field.bindStore(store); }
				else { field.store = store; }
				field._tpsTimeBound = true;
			});
		},
		applyScheduleData: function (panel, data) {
			if (!panel || !data) { return; }
			var me = this;
			me.registerScheduleFields(panel);
			me.bindTimeCombos(panel);
			var auto = me.findNamed(panel, "auto_update");
			var weekday = me.findNamed(panel, "weekday");
			var hour = me.findNamed(panel, "hour");
			var minute = me.findNamed(panel, "minute");
			var composite = me.findNamed(panel, "schedule_time_settings") ||
				me.findNamed(panel, "autoupdate_time_settings");
			if (auto && auto.setValue && data.auto_update != null) {
				auto.setValue(!!data.auto_update);
			}
			if (weekday && weekday.setValue && data.weekday != null && data.weekday !== "") {
				var w = String(data.weekday);
				if (w === "daily") { w = "0,1,2,3,4,5,6"; }
				weekday.setValue(w);
				weekday.allowBlank = true;
				if (weekday.clearInvalid) { weekday.clearInvalid(); }
			}
			function setTime(field, raw) {
				if (!field || !field.setValue || raw === undefined || raw === null || raw === "") { return; }
				var n = Number(raw);
				if (isNaN(n)) { return; }
				field.setValue(n);
			}
			setTime(hour, data.hour);
			setTime(minute, data.minute);
			if (composite && composite.setDisabled) {
				composite.setDisabled(!data.auto_update);
			}
			if (data.last_updated && panel.setLastUpdatedDate) {
				panel._tpsLastUpdated = data.last_updated;
				panel.setLastUpdatedDate(data.last_updated);
			}
		},
		applySourceData: function (panel, data) {
			if (!panel || !data) { return; }
			var form = panel.getForm && panel.getForm();
			if (!form || !form.findField) { return; }
			var use = form.findField("use_code");
			var code = form.findField("code");
			var src = data.use_code || data.source || "";
			if (src === "et-pro" || src === "etpro") { src = "etPro"; }
			if (src === "et-open" || src === "etopen") { src = "etOpen"; }
			if (use && src && use.setValue) {
				use.setValue(src);
				panel._tpsUseCode = src;
			}
			if (code && code.setValue && data.code != null) {
				code.setValue(data.code || "");
			}
			if (panel.onSelectSignatureSource && src) {
				panel.onSelectSignatureSource(src);
			}
		},
		applyScheduleFromResult: function (panel, resp) {
			var me = this;
			Ext.each((resp && resp.result) || [], function (e) {
				if (!e || !e.data) { return; }
				if (e.api === "SYNO.TPS.Settings.Update.Schedule") {
					me.applyScheduleData(panel, e.data);
				}
				if (e.api === "SYNO.TPS.Settings.Update.Source") {
					me.applySourceData(panel, e.data);
				}
				if (e.api === "SYNO.TPS.Settings.Update" && e.data.last_updated && panel.setLastUpdatedDate) {
					panel._tpsLastUpdated = e.data.last_updated;
					panel.setLastUpdatedDate(e.data.last_updated);
				}
			});
		},
		readScheduleValues: function (panel) {
			var auto = this.findNamed(panel, "auto_update");
			var weekday = this.findNamed(panel, "weekday");
			var hour = this.findNamed(panel, "hour");
			var minute = this.findNamed(panel, "minute");
			var w = weekday && weekday.getValue && weekday.getValue();
			if (w == null || w === "" || w === "daily") { w = "0,1,2,3,4,5,6"; }
			if (typeof w !== "string") { w = String(w); }
			var h = hour && hour.getValue && hour.getValue();
			var m = minute && minute.getValue && minute.getValue();
			h = (h === "" || h == null) ? 2 : Number(h);
			m = (m === "" || m == null) ? 0 : Number(m);
			if (isNaN(h)) { h = 2; }
			if (isNaN(m)) { m = 0; }
			return {
				auto_update: !!(auto && auto.getValue && auto.getValue()),
				weekday: w,
				hour: h,
				minute: m
			};
		},
		radioInputValue: function (panel, name) {
			/* syno_radio.getGroupValue walks this.el.up(...) and throws while
			   the General panel is still constructing (el is not there yet).
			   findField often returns only the first radio in the group. */
			var list = [];
			if (panel && panel.findBy) {
				try {
					list = panel.findBy(function (c) { return c && c.name === name; }) || [];
				} catch (e) { list = []; }
			}
			if (!list.length) {
				var form = panel && panel.getForm && panel.getForm();
				if (form && form.findFields) {
					try { list = form.findFields(name) || []; } catch (e2) { list = []; }
				}
				if (!list.length && form && form.findField) {
					var one = form.findField(name);
					if (one) { list = [one]; }
				}
			}
			var i, c, v, checked;
			for (i = 0; i < list.length; i++) {
				c = list[i];
				if (!c) { continue; }
				checked = c.checked;
				if (typeof c.isChecked === "function") {
					try { checked = c.isChecked(); } catch (e3) {}
				}
				try {
					v = (typeof c.getValue === "function") ? c.getValue() : checked;
				} catch (e4) { v = checked; }
				if (v === true || checked === true || v === c.inputValue) {
					return c.inputValue != null ? c.inputValue : v;
				}
				if (typeof v === "string" && v) { return v; }
			}
			return null;
		},
		findByItemId: function (panel, id) {
			if (!panel || !id) { return null; }
			if (panel.find) {
				try {
					var found = panel.find("itemId", id);
					if (found && found.length) { return found[0]; }
				} catch (e) {}
			}
			if (panel.findBy) {
				try {
					var list = panel.findBy(function (c) { return c && c.itemId === id; });
					if (list && list.length) { return list[0]; }
				} catch (e2) {}
			}
			return null;
		},
		captureModeIsCopy: function (panel) {
			if (panel && panel._tpsCaptureMode) {
				return panel._tpsCaptureMode === "copy";
			}
			return this.radioInputValue(panel, "capture_mode") === "copy";
		},
		readMirrorValues: function (panel) {
			var form = panel && panel.getForm && panel.getForm();
			function val(name, fallback) {
				var fld = form && form.findField && form.findField(name);
				if (!fld || !fld.getValue) { return fallback; }
				var v = fld.getValue();
				return (v === null || v === undefined) ? fallback : v;
			}
			var mode = (panel && panel._tpsCaptureMode) || this.radioInputValue(panel, "capture_mode") || "lan";
			return {
				capture_mode: mode === "copy" ? "copy" : "lan",
				enabled: mode === "copy",
				router_kind: this.radioInputValue(panel, "router_kind") || "openwrt",
				encap: (this.radioInputValue(panel, "router_kind") === "mikrotik") ? "tzsp" : "gretap",
				router_ip: String(val("router_ip", "") || "").replace(/^\s+|\s+$/g, ""),
				local_ip: String(val("local_ip", "") || "").replace(/^\s+|\s+$/g, ""),
				ifname: String(val("ifname", "tps0") || "tps0").replace(/^\s+|\s+$/g, "") || "tps0"
			};
		},
		setCmpEnabled: function (cmp, on) {
			if (!cmp) { return; }
			on = !!on;
			try {
				if (typeof cmp.setDisabled === "function") { cmp.setDisabled(!on); }
				else if (on && cmp.enable) { cmp.enable(); }
				else if (!on && cmp.disable) { cmp.disable(); }
			} catch (e) {}
		},
		namedField: function (panel, name) {
			var form = panel && panel.getForm && panel.getForm();
			return (form && form.findField && form.findField(name)) || this.findNamed(panel, name);
		},
		applyIdsOnlyChrome: function (panel) {
			/* Official drop-packet checkbox implies NFQUEUE IPS. This package
			   is AF_PACKET IDS only. Default mode (availability vs security) is
			   stored; it does not drop packets. Keep drop-packet off. */
			if (!panel || !panel.getForm) { return; }
			var me = this;
			var prev = this.namedField(panel, "enable_prevention");
			if (prev) {
				if (prev.setValue) { prev.setValue(false); }
				me.setCmpEnabled(prev, false);
			}
		},
		syncCaptureMode: function (panel, forced) {
			if (!panel || !panel.getForm) { return; }
			var me = this;
			var form = panel.getForm();
			if (!form) { return; }
			var copy;
			if (forced === "copy" || forced === "lan") {
				copy = forced === "copy";
				panel._tpsCaptureMode = forced;
			} else {
				copy = this.captureModeIsCopy(panel);
				panel._tpsCaptureMode = copy ? "copy" : "lan";
			}
			var sensor = this.namedField(panel, "enable_sensor");
			var sensorOn = !sensor || !sensor.getValue || !!sensor.getValue();
			var kind = this.radioInputValue(panel, "router_kind") || "openwrt";
			me.setCmpEnabled(me.namedField(panel, "router_ip"), copy);
			me.setCmpEnabled(me.namedField(panel, "local_ip"), copy && kind !== "mikrotik");
			if (form.findFields) {
				Ext.each(form.findFields("router_kind") || [], function (fld) {
					me.setCmpEnabled(fld, copy);
				});
			}
			var rip = me.namedField(panel, "router_ip");
			if (rip) {
				rip.allowBlank = !copy;
				if (!copy && rip.clearInvalid) { rip.clearInvalid(); }
			}
			/* LAN-only: Monitored Interfaces. Sensor off also disables the grid. */
			var ifaceFs = this.findByItemId(panel, "tps_iface_fieldset") ||
				(panel.interfaceGrid && panel.interfaceGrid.ownerCt);
			if (copy) {
				me.setCmpEnabled(ifaceFs, false);
				me.setCmpEnabled(panel.interfaceGrid, false);
			} else {
				me.setCmpEnabled(ifaceFs, true);
				me.setCmpEnabled(panel.interfaceGrid, sensorOn);
			}
		},
		applyMirrorData: function (panel, data) {
			if (!panel || !data) { return; }
			var form = panel.getForm && panel.getForm();
			if (!form || !form.setValues) { return; }
			form.setValues({
				capture_mode: data.capture_mode || (data.enabled ? "copy" : "lan"),
				router_kind: data.router_kind || (data.encap === "tzsp" ? "mikrotik" : "openwrt"),
				router_ip: data.router_ip || "",
				local_ip: data.local_ip || "",
				ifname: data.ifname || "tps0"
			});
			var copy = (data.capture_mode || (data.enabled ? "copy" : "lan")) === "copy";
			var kind = data.router_kind || (data.encap === "tzsp" ? "mikrotik" : "openwrt");
			var hint = form.findField("mirror_hint");
			if (hint && hint.setValue) {
				var msg = (kind === "mikrotik")
					? "MikroTik: import etc/mikrotik/apply-tps-mirror.rsc (TZSP UDP 37008). Allow that UDP from the router in DSM Firewall. Disable fasttrack or copies stay empty."
					: "OpenWrt: run etc/openwrt/apply-tps-mirror.sh. Allow GRE (protocol 47) from the router in DSM Firewall.";
				if (copy && !data.tap_present) {
					msg += " tps0 is not up yet — Apply, then restart Threat Prevention if the tap is missing.";
				}
				hint.setValue(msg);
			}
			this.syncCaptureMode(panel, copy ? "copy" : "lan");
		},
		applyMirrorFromResult: function (panel, resp) {
			var me = this;
			Ext.each((resp && resp.result) || [], function (e) {
				if (e && e.api === "SYNO.TPS.Settings.Mirror" && e.data) {
					me.applyMirrorData(panel, e.data);
				}
			});
		},
		readAccelValues: function (panel) {
			var mode = this.radioInputValue(panel, "accel_mode") || "hs";
			return { hyperscan: mode !== "ac", dpdk: false, nic_offload: false };
		},
		applyAccelData: function (panel, data) {
			if (!panel || !data) { return; }
			var me = this;
			var form = panel.getForm && panel.getForm();
			if (!form || !form.setValues) { return; }
			form.setValues({
				accel_mode: (data.hyperscan !== false && data.hyperscan_available) ? "hs" : "ac"
			});
			var hint = form.findField("accel_hint");
			if (hint && hint.setValue) {
				var msg;
				if (data.hyperscan_available) {
					msg = data.hyperscan_active
						? "Active: mpm-algo=hs, spm-algo=hs. Apply, then restart if the engine is running."
						: "Hyperscan is in this binary. Choose it and Apply to use SIMD signature matching.";
				} else {
					msg = "This Suricata binary has no Hyperscan. Matching stays ac/bmh.";
				}
				hint.setValue(msg);
			}
			if (form.findFields) {
				Ext.each(form.findFields("accel_mode") || [], function (fld) {
					if (fld && fld.inputValue === "hs") {
						me.setCmpEnabled(fld, !!data.hyperscan_available);
					} else {
						me.setCmpEnabled(fld, true);
					}
				});
			}
		},
		applyAccelFromResult: function (panel, resp) {
			var me = this;
			Ext.each((resp && resp.result) || [], function (e) {
				if (e && e.api === "SYNO.TPS.Settings.Accel" && e.data) {
					me.applyAccelData(panel, e.data);
				}
			});
		},
		accelFieldset: function () {
			return {
				xtype: "syno_fieldset",
				title: "Hardware acceleration",
				itemId: "tps_accel",
				webapi: { api: "SYNO.TPS.Settings.Accel", methods: { get: "get", set: "set" }, version: 1 },
				collapsible: false,
				defaults: { labelWidth: 160 },
				items: [
					{
						xtype: "syno_displayfield", hideLabel: true, htmlEncode: false,
						value: "Signature matching (pick one). DPDK and NIC offload are different layers; they would stack with Hyperscan, not replace it. They are not wired on this IDS package."
					},
					{
						xtype: "syno_radio", name: "accel_mode", inputValue: "hs", checked: true,
						boxLabel: "Intel Hyperscan (MPM / SPM) — recommended, SIMD"
					},
					{
						xtype: "syno_radio", name: "accel_mode", inputValue: "ac",
						boxLabel: "Portable matching (ac / bmh) — no SIMD"
					},
					{
						xtype: "syno_displayfield", hideLabel: true, htmlEncode: false, indent: 1,
						value: "Not available: Intel DPDK (userspace IO) and NIC hardware flow offload. Capture stays AF_PACKET."
					},
					{
						xtype: "syno_displayfield", name: "accel_hint", hideLabel: true, htmlEncode: false,
						value: "Uses AVX2/AVX-512 when the CPU and libhs support it. Changing this restarts Suricata."
					}
				]
			};
		},
		captureModeFieldset: function (panel) {
			var me = this;
			function onMode(fld, on) {
				if (on === false) { return; }
				me.syncCaptureMode(panel, fld && fld.name === "capture_mode" ? fld.inputValue : undefined);
				me.prepareGeneralForm(panel);
			}
			return {
				xtype: "syno_fieldset",
				title: "Capture source",
				itemId: "tps_capture_mode",
				webapi: { api: "SYNO.TPS.Settings.Mirror", methods: { get: "get", set: "set" }, version: 1 },
				collapsible: false,
				defaults: { labelWidth: 160 },
				items: [
					{
						xtype: "syno_displayfield", hideLabel: true, htmlEncode: false,
						value: "The NAS is not the gateway. Choose how Suricata sees packets."
					},
					{
						xtype: "syno_radio", name: "capture_mode", inputValue: "lan", checked: true,
						boxLabel: "Listen on NAS LAN interfaces — only traffic to or from this NAS",
						listeners: { check: onMode }
					},
					{
						xtype: "syno_radio", name: "capture_mode", inputValue: "copy",
						boxLabel: "Receive a traffic copy from the router — LAN↔WAN",
						listeners: { check: onMode }
					},
					{
						xtype: "syno_radio", name: "router_kind", inputValue: "openwrt", checked: true,
						indent: 1, disabled: true,
						boxLabel: "OpenWrt — GRE tap (nft dup onto gretap)",
						listeners: { check: onMode }
					},
					{
						xtype: "syno_radio", name: "router_kind", inputValue: "mikrotik",
						indent: 1, disabled: true,
						boxLabel: "MikroTik — TZSP stream (UDP 37008)",
						listeners: { check: onMode }
					},
					{ xtype: "hidden", name: "ifname", value: "tps0" },
					{
						xtype: "syno_textfield", name: "router_ip", fieldLabel: "Router IP",
						indent: 1, allowBlank: true, disabled: true, value: "192.168.1.1"
					},
					{
						xtype: "syno_textfield", name: "local_ip", fieldLabel: "NAS IP (optional)",
						indent: 1, allowBlank: true, disabled: true, emptyText: "auto"
					},
					{
						xtype: "syno_displayfield", name: "mirror_hint", hideLabel: true, htmlEncode: false, indent: 1,
						value: "OpenWrt: apply-tps-mirror.sh and DSM Firewall GRE (protocol 47). MikroTik: apply-tps-mirror.rsc and DSM Firewall UDP 37008. Restart the package after Apply so tps0 can be created."
					}
				]
			};
		},
		prepareGeneralForm: function (panel) {
			if (!panel || !panel.getForm) { return; }
			var me = this;
			var form = panel.getForm();
			if (!form) { return; }
			me.registerScheduleFields(panel);
			me.bindTimeCombos(panel);
			var use = form.findField("use_code");
			var code = form.findField("code");
			var isPro = use && use.getValue && use.getValue() === "etPro";
			if (code) {
				code.allowBlank = !isPro;
				if (!isPro && code.clearInvalid) { code.clearInvalid(); }
			}
			var weekday = me.findNamed(panel, "weekday");
			if (weekday) {
				weekday.allowBlank = true;
				if (weekday.clearInvalid) { weekday.clearInvalid(); }
			}
			function coerceCombo(field) {
				if (!field || !field.getValue) { return; }
				var v = field.getValue();
				if (v === "" || v === null || v === undefined) { return; }
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
			coerceCombo(me.findNamed(panel, "hour"));
			coerceCombo(me.findNamed(panel, "minute"));
			var weekdayVal = weekday && weekday.getValue && weekday.getValue();
			if (weekday && weekday.setValue && (weekdayVal === "daily" || weekdayVal === "" || weekdayVal == null)) {
				weekday.setValue("0,1,2,3,4,5,6");
				weekday.allowBlank = true;
				if (weekday.clearInvalid) { weekday.clearInvalid(); }
			}
			var store = panel.interfaceStore;
			if (!store) { return; }
			var copy = me.captureModeIsCopy(panel);
			if (copy) {
				var tap = "tps0";
				var ifname = form.findField("ifname");
				if (ifname && ifname.getValue) {
					tap = String(ifname.getValue() || "tps0").replace(/^\s+|\s+$/g, "") || "tps0";
				}
				var have = false;
				store.each(function (rec) {
					if (!rec) { return; }
					if (rec.get("if_id") === tap) {
						have = true;
						rec.set("enabled", true);
					} else {
						rec.set("enabled", false);
					}
					if (rec.commit) { rec.commit(); }
				});
				if (!have) {
					store.loadData({
						interface_list: [{
							if_id: tap, enabled: true, status: "connected",
							type: "", additional: {}
						}]
					}, true);
				}
				me.syncCaptureMode(panel);
				return;
			}
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
			me.syncCaptureMode(panel);
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
				Ext.each(names, function (name) { snap(me.findNamed(panel, name) || form.findField(name)); });
				return;
			}
			if (form.items && form.items.each) {
				form.items.each(snap);
			}
			Ext.each([
				"enable_sensor", "enable_prevention", "enable_auto_export_events_during_postupgrade",
				"network_security_mode", "auto_update", "weekday", "hour", "minute",
				"use_code", "code", "update_status", "last_updated",
				"capture_mode", "router_kind", "router_ip", "local_ip", "ifname",
				"accel_mode"
			], function (name) { snap(me.findNamed(panel, name) || form.findField(name)); });
			if (form.findFields) {
				Ext.each(form.findFields("network_security_mode") || [], snap);
				Ext.each(form.findFields("capture_mode") || [], snap);
				Ext.each(form.findFields("accel_mode") || [], snap);
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
				me.syncCaptureMode(panel);
				me.prepareGeneralForm(panel);
				if (me.captureModeIsCopy(panel)) {
					var rip = form.findField("router_ip");
					var v = rip && rip.getValue ? String(rip.getValue() || "").replace(/^\s+|\s+$/g, "") : "";
					if (!v || !/^(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/.test(v)) {
						if (rip && rip.markInvalid) { rip.markInvalid("Enter the router LAN IPv4"); }
						return false;
					}
				}
				return orig.apply(this, arguments);
			};
			form.isValid._tpsGeneral = true;
			me.prepareGeneralForm(panel);
			me.applyIdsOnlyChrome(panel);
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
								if (item.name === "enable_prevention") {
									item.disabled = true;
								}
								if (item.name === "hour" || item.name === "minute") {
									item.mode = "local";
									item.triggerAction = "all";
									item.forceSelection = true;
									item.editable = false;
									item.store = me.timeItemStore(item.name);
								}
								if (item.items) { walk(item.items); }
							});
						}
						walk(cfg && cfg.items);
						if (cfg && Ext.isArray(cfg.items) && !this._tpsCaptureSpliced) {
							this._tpsCaptureSpliced = true;
							cfg.items = cfg.items.slice();
							Ext.each(cfg.items, function (item) {
								if (!item || !item.items) { return; }
								var kids = item.items;
								if (kids === this.interfaceGrid ||
										(Ext.isArray(kids) && kids[0] === this.interfaceGrid)) {
									item.itemId = "tps_iface_fieldset";
								}
							}, this);
							cfg.items.splice(1, 0, me.captureModeFieldset(this));
							cfg.items.push(me.accelFieldset(this));
							var sensorFs = cfg.items[0];
							if (sensorFs && sensorFs.webapi && sensorFs.webapi.api === "SYNO.TPS.Sensor" && sensorFs.items) {
								sensorFs.items = (sensorFs.items || []).concat([{
									xtype: "syno_displayfield",
									name: "tps_ids_note",
									hideLabel: true,
									htmlEncode: false,
									indent: 1,
									value: "Drop high-risk packets is not available (IDS only). Default mode is saved; this engine does not drop packets when overloaded."
								}]);
							}
						}
						if (cfg && cfg.listeners) {
							cfg.listeners.afterrender = function () {
								me.applyIdsOnlyChrome(this);
								me.syncCaptureMode(this);
							};
						}
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
					P.prototype.processReturnData = function (b, a) {
						me.registerScheduleFields(this);
						me.bindTimeCombos(this);
						var ret = origReturn.apply(this, arguments);
						me.applyScheduleFromResult(this, a);
						me.applyMirrorFromResult(this, a);
						me.applyAccelFromResult(this, a);
						me.applyIdsOnlyChrome(this);
						me.syncCaptureMode(this);
						me.prepareGeneralForm(this);
						me.clearGeneralDirty(this);
						return ret;
					};
				}
				var origStatus = P.prototype.setUpdateStatus;
				if (origStatus) {
					P.prototype.setUpdateStatus = function () {
						var form = this.getForm && this.getForm();
						var use = form && form.findField && form.findField("use_code");
						var kept = (use && use.getValue && use.getValue()) || this._tpsUseCode;
						var ret = origStatus.apply(this, arguments);
						if (use && kept && use.setValue) {
							use.setValue(kept);
							this._tpsUseCode = kept;
						}
						if (this._tpsLastUpdated && this.setLastUpdatedDate) {
							var last = form && form.findField && form.findField("last_updated");
							var cur = last && last.getValue && last.getValue();
							if (!cur || cur === "--") {
								this.setLastUpdatedDate(this._tpsLastUpdated);
							}
						}
						me.clearGeneralDirty(this, ["update_status", "last_updated", "use_code", "code"]);
						return ret;
					};
				}
				var origLast = P.prototype.setLastUpdatedDate;
				if (origLast) {
					P.prototype.setLastUpdatedDate = function (a) {
						if (!a || a === "--") { a = "not_updated_yet"; }
						this._tpsLastUpdated = a;
						var ret = origLast.call(this, a);
						me.clearGeneralDirty(this, ["last_updated"]);
						return ret;
					};
				}
				P.prototype.CheckUpdateSettingsDirty = function (form, apis) {
					/* Official only tests auto_update + the composite wrapper.
					   Nested weekday/hour/minute do not mark it dirty. Always
					   include Schedule.set; processParams fills current values. */
					return apis;
				};
				var origParams = P.prototype.processParams;
				if (origParams) {
					P.prototype.processParams = function (c, b) {
						var out = origParams.apply(this, arguments);
						if (c === "get") { return out; }
						var vals = me.readScheduleValues(this);
						var mirror = me.readMirrorValues(this);
						var accel = me.readAccelValues(this);
						var copy = me.captureModeIsCopy(this);
						var form = this.getForm && this.getForm();
						var dirtyMirror = false;
						var hasMirrorSet = false;
						var dirtyAccel = false;
						var hasAccelSet = false;
						Ext.each(["capture_mode", "router_kind", "router_ip", "local_ip", "ifname"], function (name) {
							var fld = form && form.findField && form.findField(name);
							if (fld && fld.isDirty && fld.isDirty()) { dirtyMirror = true; }
						});
						if (form && form.findFields) {
							Ext.each(form.findFields("accel_mode") || [], function (fld) {
								if (fld && fld.isDirty && fld.isDirty()) { dirtyAccel = true; }
							});
						}
						Ext.each(out || [], function (f) {
							if (!f) { return; }
							if (f.api === "SYNO.TPS.Settings.Update.Schedule" && f.method !== "get") {
								f.params = Ext.apply({}, f.params || {}, vals);
							}
							if (f.api === "SYNO.TPS.Settings.Mirror" && f.method === "set") {
								hasMirrorSet = true;
								f.params = Ext.apply({}, f.params || {}, mirror);
							}
							if (f.api === "SYNO.TPS.Settings.Accel" && f.method === "set") {
								hasAccelSet = true;
								f.params = Ext.apply({}, f.params || {}, accel);
							}
							if (f.api === "SYNO.TPS.Sensor" && f.method === "set" && copy) {
								f.params = f.params || {};
								f.params.interface_list = [{ if_id: mirror.ifname || "tps0", enabled: true }];
							}
						});
						if (dirtyMirror && !hasMirrorSet) {
							out = (out || []).concat([{
								api: "SYNO.TPS.Settings.Mirror", method: "set", version: 1, params: mirror
							}]);
						}
						if (dirtyAccel && !hasAccelSet) {
							out = (out || []).concat([{
								api: "SYNO.TPS.Settings.Accel", method: "set", version: 1, params: accel
							}]);
						}
						return out;
					};
				}
				var origEnable = P.prototype.onEnableSensorChecked;
				if (origEnable) {
					P.prototype.onEnableSensorChecked = function () {
						var ret = origEnable.apply(this, arguments);
						me.applyIdsOnlyChrome(this);
						me.syncCaptureMode(this);
						return ret;
					};
				}
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
			this.whenClass(tryPatch, !!Panel);
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
			this.whenClass(tryPatch, false);
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
				if (name === "SYNO.SDS.TPS.Ruleset.RuleGridPanel") {
					me.patchRuleGridCombo(cls);
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
		telegramSecretNames: ["tg_token", "tg_chat_id"],
		isKeptTelegramToken: function (v) {
			v = String(v || "").trim();
			if (!v) { return true; }
			return /^[\u2022*•]+$/.test(v);
		},
		fieldInput: function (fld) {
			if (!fld || !fld.el) { return null; }
			var input = fld.el.dom;
			if (input && String(input.tagName || "").toLowerCase() !== "input") {
				input = (fld.el.child && fld.el.child("input", true)) ||
					(fld.el.query && fld.el.query("input")[0]);
			}
			return input || null;
		},
		fieldRaw: function (fld) {
			if (!fld) { return ""; }
			var input = this.fieldInput(fld);
			var raw = (input && input.value) || "";
			if (!raw && fld.getRawValue) { raw = fld.getRawValue(); }
			if (!raw && fld.getValue) { raw = fld.getValue(); }
			return raw == null ? "" : String(raw);
		},
		setFieldInputType: function (fld, type) {
			if (!fld) { return; }
			fld.inputType = type;
			var input = this.fieldInput(fld);
			if (!input) { return; }
			try {
				input.type = type;
			} catch (e) {
				try { input.setAttribute("type", type); } catch (e2) { /* IE */ }
			}
		},
		telegramShowButton: function (panel) {
			var found = panel && panel.find && panel.find("itemId", "btn_telegram_show");
			return (found && found[0]) || null;
		},
		applyTelegramSecretVisibility: function (panel) {
			var me = this;
			var show = !!(panel && panel._tpsShowSecrets);
			var f = panel && panel.getForm && panel.getForm();
			if (f) {
				Ext.each(this.telegramSecretNames, function (name) {
					me.setFieldInputType(f.findField(name), show ? "text" : "password");
				});
			}
			var btn = this.telegramShowButton(panel);
			if (btn && btn.setText) {
				btn.setText(show ? "Hide values" : "Show values");
			}
		},
		toggleTelegramSecrets: function (panel) {
			panel._tpsShowSecrets = !panel._tpsShowSecrets;
			this.applyTelegramSecretVisibility(panel);
		},
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
				if (!this._tpsTelegramSaving) { me.loadTelegramInto(this); }
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
					{xtype: "syno_textfield", name: "tg_chat_id", fieldLabel: "Chat ID", inputType: "password", indent: 1, value: ""},
					{xtype: "syno_button", itemId: "btn_telegram_show", text: "Show values", indent: 1, handler: function () { me.toggleTelegramSecrets(panel); }},
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
			var me = this;
			var f = panel && panel.getForm && panel.getForm();
			if (!f) { return {}; }
			function val(name, fallback) {
				var fld = f.findField(name);
				if (!fld) { return fallback; }
				var xt = String(fld.xtype || "");
				if (xt.indexOf("check") !== -1) {
					return fld.getValue ? fld.getValue() : fallback;
				}
				var raw = me.fieldRaw(fld);
				if (raw !== "") { return raw; }
				return fallback;
			}
			var minutes = Number(val("min_interval_telegram", 5));
			if (!isFinite(minutes) || minutes < 0) { minutes = 5; }
			var payload = {
				enable_telegram: !!val("enable_telegram", false),
				follow_mail: val("telegram_follow_mail", true) !== false,
				min_interval_telegram: Math.round(minutes * 60)
			};
			var token = val("tg_token", "") || "";
			var chat = val("tg_chat_id", "") || "";
			/* DSM Ajax injects CSRF as `token`. Always send bot_token. */
			if (token && !me.isKeptTelegramToken(token)) { payload.bot_token = token; }
			if (chat && !me.isKeptTelegramToken(chat)) { payload.chat_id = chat; }
			return payload;
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
				set("tg_token", data.bot_token || data.token || "");
				var sec = Number(data.min_interval_telegram);
				if (!isFinite(sec) || sec < 0) { sec = 300; }
				set("min_interval_telegram", Math.round(sec / 60));
				me.applyTelegramSecretVisibility(panel);
				me.clearTelegramDirty(panel);
				window.setTimeout(function () {
					me.applyTelegramSecretVisibility(panel);
					me.clearTelegramDirty(panel);
				}, 0);
				window.setTimeout(function () {
					me.applyTelegramSecretVisibility(panel);
					me.clearTelegramDirty(panel);
				}, 50);
			});
		},
		saveTelegramFrom: function (panel) {
			var me = this;
			var payload = this.telegramFromForm(panel);
			panel._tpsTelegramSaving = true;
			this.call("SYNO.TPS.Settings.Telegram", "set", 1, payload, function (ok) {
				panel._tpsTelegramSaving = false;
				if (ok) {
					me.loadTelegramInto(panel);
					return;
				}
				me.clearTelegramDirty(panel);
			});
		},
		testTelegram: function (panel) {
			var p = this.telegramFromForm(panel);
			this.call("SYNO.TPS.Settings.Telegram", "test", 1, {
				bot_token: p.bot_token || "",
				chat_id: p.chat_id || ""
			}, function (ok) {
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
				pruneModifiedRecords: true,
				fields: [
					{name: "id"}, {name: "name"}, {name: "url"}, {name: "enabled"}
				]
			});
			function loadRows(feeds, pending) {
				var rows = [];
				Ext.each(feeds || [], function (f) {
					rows.push({
						id: f.id,
						name: f.name,
						url: f.url,
						enabled: !!f.enabled
					});
				});
				store.loadData(rows);
				if (pending) {
					store.each(function (r) {
						var id = String(r.get("id"));
						if (pending.hasOwnProperty(id)) {
							r.set("enabled", pending[id]);
						}
					});
				}
			}
			function pendingEnabled() {
				var pending = {};
				Ext.each(store.getModifiedRecords() || [], function (r) {
					pending[String(r.get("id"))] = !!r.get("enabled");
				});
				return pending;
			}
			function reload(keep) {
				var pending = keep ? pendingEnabled() : null;
				me.call("SYNO.TPS.Settings.Feed", "list", 1, {}, function (ok, data) {
					loadRows((ok && data && data.feeds) || [], pending);
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
					useDefaultBtn: false,
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
								reload(true);
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
					width: 56,
					fixed: true,
					resizable: false,
					align: "center",
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
					me.call("SYNO.TPS.Settings.Feed", "delete", 1, {id: rec.get("id")}, function () { reload(true); });
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
			function modifiedFeeds() {
				var feeds = [];
				Ext.each(store.getModifiedRecords() || [], function (r) {
					feeds.push({ id: r.get("id"), enabled: !!r.get("enabled") });
				});
				return feeds;
			}
			var Helper = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Utils && SYNO.SDS.TPS.Utils.Helper;
			panel = new Form({
				title: "Rule Feeds",
				itemId: "SYNO.SDS.TPS.Settings.FeedPanel",
				cls: "syno-sds-ips-settings-device-panel",
				padding: "0px 12px 0px 0px",
				trackResetOnLoad: true,
				useDefaultBtn: true,
				helper: Helper,
				layout: "vbox",
				layoutConfig: {align: "stretch"},
				items: [
					{xtype: "container", layout: "form", autoHeight: true, items: [
						{xtype: "syno_displayfield", hideLabel: true, htmlEncode: false, value: "Community sources from the OISF index are listed here, <b>off by default</b>. Enable the ones you want (or Add your own HTTPS URL), then <b>Apply</b>. They apply on top of ET Open/Pro. Run Update Now on General after Apply."}
					]},
					grid
				],
				listeners: {activate: function () { reload(false); }},
				processParams: function (method, apis) {
					apis = apis || [];
					if (method === "set") {
						apis.push({
							api: "SYNO.TPS.Settings.Feed",
							method: "save",
							version: 1,
							params: { feeds: modifiedFeeds() }
						});
					}
					apis.push({ api: "SYNO.TPS.Settings.Feed", method: "list", version: 1 });
					return apis;
				},
				processReturnData: function (ok, data) {
					data = data || {};
					if (data.has_fail) { return; }
					var rows = null;
					Ext.each(data.result || [], function (item) {
						if (item && item.api === "SYNO.TPS.Settings.Feed" && item.method === "list" && item.data) {
							rows = item.data.feeds;
						}
					});
					if (!rows && data.feeds) { rows = data.feeds; }
					if (rows) { loadRows(rows); }
				}
			});
			var form = panel.getForm && panel.getForm();
			if (form && !form._tpsFeedDirty) {
				form._tpsFeedDirty = true;
				var origDirty = form.isDirty;
				form.isDirty = function () {
					if ((store.getModifiedRecords() || []).length) { return true; }
					return origDirty ? origDirty.apply(this, arguments) : false;
				};
				var origReset = form.reset;
				form.reset = function () {
					store.each(function (r) { r.reject(); });
					return origReset ? origReset.apply(this, arguments) : this;
				};
			}
			return panel;
		}
	};
	var k;
	for (k in extra) {
		if (Object.prototype.hasOwnProperty.call(extra, k)) { B[k] = extra[k]; }
	}
}(SYNO.SDS.TPS.Bridge));

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
