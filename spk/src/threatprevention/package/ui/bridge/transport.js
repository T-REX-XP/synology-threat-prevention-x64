/* Pack-time part 1/3. Concat order: transport.js, dsm7.js, settings-inject.js
   prepended into synoips.js. Do not register these as ui/config modules. */
window.SYNO = window.SYNO || {};
SYNO.SDS = SYNO.SDS || {};
SYNO.SDS.TPS = SYNO.SDS.TPS || {};
if (window.Ext && Ext.namespace) {
	Ext.namespace("SYNO.SDS.TPS");
}
SYNO.SDS.TPS.Bridge = SYNO.SDS.TPS.Bridge || {};
(function (B) {
	var extra = {
		base: function () {
			return "/webman/tps-api";
		},
		legacyBase: function () {
			return "/webman/3rdparty/ThreatPrevention/api";
		},
		apis: [
			"SYNO.TPS.Backup", "SYNO.TPS.Device", "SYNO.TPS.Event", "SYNO.TPS.Event.ExportFolder",
			"SYNO.TPS.Event.Map", "SYNO.TPS.Event.Offset", "SYNO.TPS.Event.Statistic",
			"SYNO.TPS.Notification", "SYNO.TPS.Notification.Filter", "SYNO.TPS.Sensor",
			"SYNO.TPS.Sensor.Variables", "SYNO.TPS.Settings.Storage", "SYNO.TPS.Settings.Update",
			"SYNO.TPS.Settings.Update.Schedule", "SYNO.TPS.Settings.Update.Source",
			"SYNO.TPS.Settings.Telegram", "SYNO.TPS.Settings.Mirror", "SYNO.TPS.Settings.Feed",
			"SYNO.TPS.Settings.Map", "SYNO.TPS.Compound",
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
					fire(false, { success: false, error: { code: 404 } });
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
		shouldStealRequest: function (opts) {
			/* DSM desktop polling uses SYNO.API.Request({compound}) and expects
			   data.reg_ref. Never steal those, or any Polling.* API. */
			if (!opts) { return false; }
			var api = opts.api || (opts.webapi && opts.webapi.api) || "";
			if (String(api).indexOf("Polling") !== -1) { return false; }
			if (this.isPollingCallback(opts.callback || opts.status_callback)) { return false; }
			if (opts.compound && opts.compound.params) {
				return this.compoundHasHosted(opts.compound);
			}
			return this.isHosted(api);
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
			if (!this.shouldStealRequest(opts)) { return fallback(); }
			if (opts.compound && opts.compound.params) {
				return this.compound(opts);
			}
			var api = opts.api || (opts.webapi && opts.webapi.api);
			var method = opts.method || (opts.webapi && opts.webapi.method);
			var version = opts.version || (opts.webapi && opts.webapi.version) || 1;
			var params = opts.params || (opts.webapi && opts.webapi.params) || {};
			this.call(api, method, version, params, opts.callback || opts.status_callback, opts.scope);
			return true;
		},
		compound: function (opts) {
			var me = this;
			var items = this.orderCompound(opts.compound.params || []);
			var out = [];
			var left = items.length;
			var failed = false;
			if (!left) {
				if (opts.callback) { opts.callback.call(opts.scope || window, true, { result: [], has_fail: false }); }
				return true;
			}
			var allHosted = true;
			Ext.each(items, function (it) {
				if (!it || !me.isHosted(it.api)) { allHosted = false; }
			});
			if (allHosted) {
				me.call("SYNO.TPS.Compound", "request", 1, { compound: items }, function (ok, data) {
					var payload = {
						result: (data && data.result) || [],
						has_fail: !ok || !!(data && data.has_fail)
					};
					Ext.each(items, function (item) {
						if (item && item.api === "SYNO.TPS.Notification" && item.method === "set") {
							var panel = opts.scope;
							if (panel && panel.getForm && panel.getForm().findField("enable_telegram")) {
								me.saveTelegramFrom(panel);
							}
						}
					});
					if (opts.callback) {
						opts.callback.call(opts.scope || window, ok && !payload.has_fail, payload, { compound: items });
					}
				}, opts.scope);
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
					opts.callback.call(opts.scope || window, true, { result: out, has_fail: failed }, { compound: items });
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
		orderCompound: function (items) {
			var rank = {
				"SYNO.TPS.Settings.Mirror|set": 0,
				"SYNO.TPS.Sensor|set": 1,
				"SYNO.TPS.Settings.Update.Schedule|set": 2,
				"SYNO.TPS.Settings.Update.Source|set": 3
			};
			var tagged = [];
			Ext.each(items || [], function (it, i) {
				var key = (it && it.api ? it.api : "") + "|" + (it && it.method ? it.method : "");
				tagged.push({ i: i, it: it, r: rank.hasOwnProperty(key) ? rank[key] : 50 });
			});
			tagged.sort(function (a, b) { return a.r === b.r ? a.i - b.i : a.r - b.r; });
			var out = [];
			Ext.each(tagged, function (t) { out.push(t.it); });
			return out;
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
			function fire(cb, scope, ok, data, raw, reqCompound) {
				var envelope = data || {};
				var extra = {};
				var items = reqCompound && reqCompound.params ? reqCompound.params : reqCompound;
				if (Ext.isArray(items)) { extra.compound = items; }
				var fake = {
					status: ok ? 200 : 500,
					responseData: envelope,
					responseText: Ext.encode({ success: !!ok, data: envelope })
				};
				if (cb) { cb.call(scope || window, ok, envelope, extra, {}, fake); }
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
						callback: function (ok, data) { fire(cb, scope, ok, data, data, compound); }
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
		patchSignatureUpdater: function () {
			/* Official update()/startCheck() ignore the returned task_id and
			   pollList() for DSM jobs named SYNO.TPS_Updater. We never register
			   those, so Update Now fell through to start_check (HEAD probe) and
			   never watched the real download. Poll Update.status on our job. */
			var me = this;
			function tryPatch() {
				var U = window.SYNO && SYNO.SDS && SYNO.SDS.TPS && SYNO.SDS.TPS.Utils &&
					SYNO.SDS.TPS.Utils.SignatureUpdater;
				if (!U || !U.checkStatus || U._tpsUpdater) { return !!(U && U._tpsUpdater); }
				U._tpsUpdater = true;
				U.update = function () {
					var self = this;
					SYNO.Debug("start updating");
					this.response.data.status = "updating";
					this.getComponent().sendWebAPI({
						api: "SYNO.TPS.Settings.Update",
						method: "start_update",
						version: 1,
						scope: this,
						callback: function (ok, data) {
							if (ok && data && data.task_id) {
								self.taskId = data.task_id;
								self.checkStatus();
								return;
							}
							if (data) { self.helper.getErrorMsg(data.code, data.isTimeout); }
							else { self.helper.getErrorMsg("update error"); }
						}
					});
				};
				U.startCheck = function () {
					var self = this;
					SYNO.Debug("sending SYNO.TPS.Settings.Update.start_check");
					this.response = { data: { status: "checking", last_updated: (this.response && this.response.data && this.response.data.last_updated) || "--" } };
					this.getComponent().sendWebAPI({
						api: "SYNO.TPS.Settings.Update",
						method: "start_check",
						version: 1,
						scope: this,
						callback: function (ok, data) {
							if (ok && data && data.task_id) {
								self.taskId = data.task_id;
								self.checkStatus();
								return;
							}
							if (data) { self.helper.getErrorMsg(data.code, data.isTimeout); }
							else { self.helper.getErrorMsg("startCheck error"); }
						}
					});
				};
				return true;
			}
			if (tryPatch()) { return; }
			var n = 0;
			var id = window.setInterval(function () {
				if (tryPatch() || ++n > 80) { window.clearInterval(id); }
			}, 25);
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
				me.injectGridComboCss();
				me.hookManagerRequest();
				return;
			}
			me.injectInfo();
			me.injectModuleListCss();
			me.injectGridComboCss();
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
			function wrapPollList(cls) {
				if (!cls || !cls.prototype || !cls.prototype.pollList || cls.prototype.pollList._tpsBridge) { return; }
				var origList = cls.prototype.pollList;
				cls.prototype.pollList = function (opts) {
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
					return origList.apply(this, arguments);
				};
				cls.prototype.pollList._tpsBridge = true;
			}
			wrapPollList(Ext.Component);
			wrapPollList(SYNO.SDS.AppWindow);
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
					if (me.shouldStealRequest(opts)) {
						return me.dispatch(opts, function () { return origReq.apply(this, args); });
					}
					return origReq.apply(this, arguments);
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
			me.patchRuleGridCombo();
			me.injectSettingsTabs();
			me.hookPolling();
			me.patchSignatureUpdater();
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
	var k;
	for (k in extra) {
		if (Object.prototype.hasOwnProperty.call(extra, k)) { B[k] = extra[k]; }
	}
}(SYNO.SDS.TPS.Bridge));
