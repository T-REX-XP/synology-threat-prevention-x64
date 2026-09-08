/* Pack-time part 2/3 — DSM 7 widget patches (htmlEncode, sprites, maps, Overview). */
window.SYNO = window.SYNO || {};
SYNO.SDS = SYNO.SDS || {};
SYNO.SDS.TPS = SYNO.SDS.TPS || {};
if (window.Ext && Ext.namespace) {
	Ext.namespace("SYNO.SDS.TPS");
}
SYNO.SDS.TPS.Bridge = SYNO.SDS.TPS.Bridge || {};
(function (B) {
	var extra = {
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
		injectGridComboCss: function () {
			/* DSM 7 EditorGrid marks combo cells syno-ux-triggerfield and draws
			   combo_trigger.png on ::after. Official SRM actionRenderer also
			   injects an <img> trigger, so two glyphs stack into a "mask". Hide
			   the fake img and leave DSM's ::after. */
			if (document.getElementById("tps-grid-combo-css")) { return; }
			var css = [
				".syno-ux-editorgridpanel .x-grid3-cell.syno-ux-triggerfield img.x-form-trigger,",
				".syno-ux-gridpanel .x-grid3-cell.syno-ux-triggerfield img.x-form-trigger,",
				".syno-ux-editorgridpanel .x-grid3-cell .tps-grid-combo-trigger,",
				".syno-ux-gridpanel .x-grid3-cell .tps-grid-combo-trigger { display: none !important; }",
				".syno-ux-editorgridpanel .x-grid3-cell.syno-ux-triggerfield .tps-grid-combo,",
				".syno-ux-gridpanel .x-grid3-cell.syno-ux-triggerfield .tps-grid-combo {",
				"  height: auto; padding: 0; overflow: visible; border: 0; background: transparent;",
				"}"
			].join("\n");
			var el = document.createElement("style");
			el.id = "tps-grid-combo-css";
			el.type = "text/css";
			if (el.styleSheet) { el.styleSheet.cssText = css; }
			else { el.appendChild(document.createTextNode(css)); }
			(document.head || document.getElementsByTagName("head")[0] || document.body).appendChild(el);
		},
		patchRuleGridCombo: function (Panel) {
			var me = this;
			function tryPatch() {
				var P = Panel;
				if (!P || !P.prototype) {
					P = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Ruleset &&
						SYNO.SDS.TPS.Ruleset.RuleGridPanel;
				}
				if (!P || !P.prototype || !P.prototype.actionRenderer) { return false; }
				if (P.prototype._tpsActionCombo) { return true; }
				P.prototype._tpsActionCombo = true;
				P.prototype.actionRenderer = function (c) {
					var label = this.helper.T("ruleset", "action_" + String(c || "alert").toLowerCase());
					return Ext.util.Format.htmlEncode(label);
				};
				return true;
			}
			this.whenClass(tryPatch, !!Panel);
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
		ensureOverviewIdsNote: function (panel) {
			if (!panel || !window.Ext) { return; }
			var box = panel.statusContainerId && Ext.getCmp(panel.statusContainerId);
			if (!box || !box.add) { return; }
			if (box.getComponent && box.getComponent("tps_ids_note")) { return; }
			try {
				box.add({
					xtype: "syno_displayfield",
					itemId: "tps_ids_note",
					hideLabel: true,
					htmlEncode: false,
					cls: "syno-ux-note note-font",
					margins: "8 0 0 0",
					value: "IDS only — this NAS does not drop packets (no inline IPS)."
				});
				if (panel.doLayout) { panel.doLayout(); }
				else if (box.doLayout) { box.doLayout(); }
			} catch (e) { /* status container not ready */ }
		},
		ensureOverviewCapNote: function (panel, data) {
			if (!panel || !window.Ext) { return; }
			var box = panel.statusContainerId && Ext.getCmp(panel.statusContainerId);
			if (!box || !box.add) { return; }
			var existing = box.getComponent && box.getComponent("tps_cap_note");
			if (!data || data.capture_capable !== false) {
				if (existing && box.remove) {
					try { box.remove(existing, true); } catch (e0) { /* already gone */ }
				}
				return;
			}
			var html = "Capture needs file capabilities. As admin run:<br><code>/usr/bin/setcap cap_net_raw,cap_net_admin,cap_ipc_lock+ep /var/packages/ThreatPrevention/target/bin/suricata</code><br>then restart the package.";
			if (existing) {
				if (existing.setValue) { existing.setValue(html); }
				return;
			}
			try {
				box.add({
					xtype: "syno_displayfield",
					itemId: "tps_cap_note",
					hideLabel: true,
					htmlEncode: false,
					cls: "syno-ux-note note-font",
					margins: "8 0 0 0",
					value: html
				});
				if (panel.doLayout) { panel.doLayout(); }
				else if (box.doLayout) { box.doLayout(); }
			} catch (e) { /* status container not ready */ }
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
						me.ensureOverviewIdsNote(this);
						me.ensureOverviewCapNote(this, this._tpsSensorData);
						window.setTimeout(function () {
							me.bindStatusPathlinks(self);
							me.ensureOverviewIdsNote(self);
							me.ensureOverviewCapNote(self, self._tpsSensorData);
						}, 0);
						return ret;
					};
				}
				var origSensorCb = P.prototype.sensorStatusCallback;
				if (origSensorCb && !P.prototype.sensorStatusCallback._tpsCap) {
					P.prototype.sensorStatusCallback = function (ok, data) {
						var ret = origSensorCb.apply(this, arguments);
						if (ok && data) { this._tpsSensorData = data; }
						me.ensureOverviewIdsNote(this);
						me.ensureOverviewCapNote(this, this._tpsSensorData);
						return ret;
					};
					P.prototype.sensorStatusCallback._tpsCap = true;
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
			this.whenClass(tryPatch, !!Panel);
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
		}
	};
	var k;
	for (k in extra) {
		if (Object.prototype.hasOwnProperty.call(extra, k)) { B[k] = extra[k]; }
	}
}(SYNO.SDS.TPS.Bridge));
