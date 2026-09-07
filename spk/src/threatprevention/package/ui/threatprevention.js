/* Community ExtJS shell. Original code — not Synology synoips.js.
   The SPA is webpack-built into index.html and loaded in an iframe so HTTPS DSM
   can call same-origin /webman/3rdparty/ThreatPrevention/api. */
Ext.namespace("SYNO.SDS.ThreatPrevention");

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
		var src = "/webman/3rdparty/ThreatPrevention/index.html";
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
			items: [{
				xtype: "box",
				autoEl: {
					tag: "iframe",
					src: src,
					frameborder: "0",
					style: "border:0;width:100%;height:100%;background:#f5f5f7;"
				}
			}]
		}, cfg));
	},
	onOpen: function () {
		SYNO.SDS.ThreatPrevention.MainWindow.superclass.onOpen.apply(this, arguments);
	},
	onClose: function () {
		SYNO.SDS.ThreatPrevention.MainWindow.superclass.onClose.apply(this, arguments);
		this.doClose();
		return true;
	}
});
