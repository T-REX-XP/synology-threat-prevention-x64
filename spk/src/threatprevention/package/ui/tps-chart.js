/* DSM 7 has no SYNO.SDS.Chart.* (those widgets are SRM-only).
   Official synoips.js depends on LineChart / PieChart / CreateAxis.
   This file is a JSLoad module so those names exist before Overview constructs. */
(function (w) {
	w.SYNO = w.SYNO || {};
	SYNO.SDS = SYNO.SDS || {};
	SYNO.SDS.Chart = SYNO.SDS.Chart || {};

	function emptyFn() {}

	SYNO.SDS.Chart.CreateAxis = SYNO.SDS.Chart.CreateAxis || function (cfg) {
		cfg = cfg || {};
		return {
			type: cfg.type || "default",
			ticks: cfg.ticks || 0,
			tickPadding: cfg.tickPadding || 0,
			max: cfg.max || 0,
			tickFormatter: cfg.tickFormatter || (w.Ext && Ext.emptyFn) || emptyFn
		};
	};

	function define() {
		if (!w.Ext || !Ext.extend) { return false; }
		if (SYNO.SDS.Chart.LineChart && SYNO.SDS.Chart.LineChart.prototype && SYNO.SDS.Chart.LineChart.prototype.setChartItems) {
			return true;
		}
		var Base = Ext.BoxComponent || Ext.Component;
		if (!Base) { return false; }
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
			pointY: function (pt) {
				if (Ext.isArray(pt)) { return Number(pt[1]) || 0; }
				return Number(pt && (pt.y !== undefined ? pt.y : pt[1])) || 0;
			},
			hasSeriesData: function (items) {
				var found = false, me = this;
				Ext.each(items || [], function (series) {
					Ext.each((series && series.data) || [], function (pt) {
						if (me.pointY(pt)) { found = true; }
					});
				});
				return found;
			},
			setChartItems: function (items) {
				this.chartItems = items || [];
				var max = 0, me = this;
				Ext.each(this.chartItems, function (series) {
					Ext.each(series.data || [], function (pt) {
						var y = me.pointY(pt);
						if (y > max) { max = y; }
					});
				});
				this.axisY = this.axisY || {};
				this.axisY.max = max || 1;
			},
			draw: function () {
				if (!this.el || !this.el.dom) { return; }
				var wdt = this.el.getWidth() || 400, h = this.el.getHeight() || 210;
				if (!this.hasSeriesData(this.chartItems)) {
					this.el.update(
						'<div class="syno-ux-note note-font tps-chart-empty" style="padding:32px 12px;color:#666;text-align:center;">No trend data yet</div>'
					);
					return;
				}
				var pad = this.chartPaddings || {};
				var left = pad.left || 38, bottom = pad.bottom || 22, top = pad.top || 6, right = pad.right || 0;
				var iw = Math.max(10, wdt - left - right), ih = Math.max(10, h - top - bottom);
				var max = (this.axisY && this.axisY.max) || 1;
				var paths = [];
				var me = this;
				Ext.each(this.chartItems, function (series) {
					var pts = series.data || [];
					if (!pts.length) { return; }
					var n = pts.length;
					var d = [];
					Ext.each(pts, function (pt, i) {
						var x = left + (n <= 1 ? iw / 2 : (iw * i / (n - 1)));
						var yv = me.pointY(pt);
						var y = top + ih - (ih * yv / max);
						d.push((i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1));
					});
					paths.push('<path d="' + d.join(" ") + '" fill="none" stroke="' + (series.color || "#2A588C") + '" stroke-width="' + (series.width || 2) + '"/>');
				});
				this.el.update('<svg width="' + wdt + '" height="' + h + '" xmlns="http://www.w3.org/2000/svg">' + paths.join("") + "</svg>");
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
				var wdt = this.initialConfig.width || 128, h = this.initialConfig.height || 136;
				if (!total) {
					this.el.update(
						'<div class="syno-ux-note note-font tps-chart-empty" style="width:' + wdt +
							"px;height:" + h + 'px;color:#888;font-size:11px;text-align:center;line-height:' +
							h + 'px;">No events in this period</div>'
					);
					return;
				}
				var r = this.initialConfig.radius || 58;
				var ir = this.initialConfig.innerRadius || 20;
				var cx = wdt / 2, cy = h / 2;
				var a0 = -Math.PI / 2, parts = [];
				Ext.each(items, function (it) {
					var frac = (Number(it.data) || 0) / total;
					var a1 = a0 + frac * Math.PI * 2;
					var x0 = cx + r * Math.cos(a0), y0 = cy + r * Math.sin(a0);
					var x1 = cx + r * Math.cos(a1), y1 = cy + r * Math.sin(a1);
					var large = frac > 0.5 ? 1 : 0;
					parts.push('<path d="M ' + cx + " " + cy + " L " + x0.toFixed(1) + " " + y0.toFixed(1) + " A " + r + " " + r + " 0 " + large + " 1 " + x1.toFixed(1) + " " + y1.toFixed(1) + ' Z" fill="' + (it.color || "#2A588C") + '"/>');
					a0 = a1;
				});
				this.el.update('<svg width="' + wdt + '" height="' + h + '">' + parts.join("") + '<circle cx="' + cx + '" cy="' + cy + '" r="' + ir + '" fill="#fff"/></svg>');
			}
		});
		return true;
	}

	if (define()) { return; }
	if (w.Ext && Ext.onReady) {
		Ext.onReady(define);
	} else {
		var n = 0, t = w.setInterval(function () {
			if (define() || ++n > 50) { w.clearInterval(t); }
		}, 20);
	}
}(window));
