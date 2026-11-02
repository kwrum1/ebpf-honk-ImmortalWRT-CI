'use strict';
'require baseclass';
'require fs';
'require rpc';

/* Homepage widget for the eBPF fastpath.
 *
 * LuCI's status overview lists /www/luci-static/resources/view/status/include
 * and requires every *.js in it (sorted by name), so shipping this file from
 * luci-app-ebpf is enough to get a card next to "System"/"Memory" -- no patch
 * to luci-mod-status.
 *
 * Data comes from `dpdctl status -j` (one exec per poll); when rpcd does not
 * allow the exec, it falls back to /var/run/ebpf/status.json, which the
 * gate watchdog rewrites every 20 s.
 */

var callExec = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params' ],
	expect: { stdout: '' }
});

function num(v) {
	return Number(v) || 0;
}

function fmtBytes(n) {
	n = num(n);

	var unit = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB' ];
	var i = 0;

	while (n >= 1024 && i < unit.length - 1) {
		n /= 1024;
		i++;
	}

	return (i ? n.toFixed(1) : String(n)) + ' ' + unit[i];
}

function fmtRate(bps) {
	bps = num(bps);

	if (bps >= 1e9)
		return (bps / 1e9).toFixed(2) + ' Gbit/s';
	if (bps >= 1e6)
		return (bps / 1e6).toFixed(1) + ' Mbit/s';
	if (bps >= 1e3)
		return (bps / 1e3).toFixed(0) + ' kbit/s';

	return bps.toFixed(0) + ' bit/s';
}

function fmtNum(n) {
	return num(n).toLocaleString();
}

/* previous sample, used to turn cumulative counters into a rate */
var prev = null;

function rate(stats) {
	var now = Date.now();
	var cur = { t: now, bytes: num(stats.bytes), pkts: num(stats.pkt_total) };
	var out = { bps: 0, pps: 0 };

	if (prev && cur.t > prev.t) {
		var dt = (cur.t - prev.t) / 1000;

		out.bps = Math.max(0, (cur.bytes - prev.bytes) * 8 / dt);
		out.pps = Math.max(0, (cur.pkts - prev.pkts) / dt);
	}

	prev = cur;
	return out;
}

return baseclass.extend({
	title: _('eBPF 加速'),

	load: function() {
		return callExec('/usr/sbin/dpdctl', [ 'status', '-j' ])
			.then(function(res) {
				try { return JSON.parse(res.stdout); } catch (e) { return null; }
			})
			.catch(function() {
				return fs.read('/var/run/ebpf/status.json')
					.then(function(text) { try { return JSON.parse(text); } catch (e) { return null; } })
					.catch(function() { return null; });
			});
	},

	render: function(st) {
		if (!st || !st.attached) {
			return E('p', { 'class': 'cbi-value-description' }, [
				_('数据面未加载（dpd-fastpath 未启动或没有权限读取状态）。')
			]);
		}

		var cfg = st.cfg || {};
		var mt  = st.maps || {};
		var s   = st.stats || {};
		var g   = st.gate || {};
		var r   = rate(s);
		var mode = cfg.mode || '?';
		var ok = (mode == 'stateful' || mode == 'stateless');

		var rows = [];

		function row(label, value, hint) {
			rows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td', 'style': 'width:11em' }, [ label ]),
				E('td', { 'class': 'td' }, [ value ]),
				hint ? E('td', { 'class': 'td cbi-value-description' }, [ hint ]) : E('td', { 'class': 'td' }, [])
			]));
		}

		row(_('模式'),
			E('span', {
				'class': ok ? 'label success' : 'label warning'
			}, [ mode ]),
			g.code && g.code != 'ok'
				? E('span', {}, [ g.code + ' — ' + (g.reason || '') ])
				: _('已接管转发'));

		row(_('已加速'),
			fmtNum(s.flow_hit),
			_('字节 %s / 流表 %s 条').format(
				fmtBytes(s.bytes),
				fmtNum((mt.flows && mt.flows.max_entries) || 0)));

		row(_('实时'),
			(ok ? fmtRate(r.bps) : '—'),
			(ok ? fmtNum(Math.round(r.pps)) + ' pps' : ''));

		row(_('出口'),
			fmtNum(s.redirect_ok) + ' / ' + fmtNum(s.neigh_ok),
			_('L2 直发 / redirect_neigh（失败 %s）').format(fmtNum(s.neigh_fail)));

		if (num(s.mss_clamp) || num(s.mss_skip))
			row(_('MSS 改写'), fmtNum(s.mss_clamp),
				_('跳过 %s（出口 MTU 未知或低于 536）').format(fmtNum(s.mss_skip)));

		if (num(s.tag_pop) || num(s.tag_skip))
			row(_('VLAN 摘 tag'), fmtNum(s.tag_pop),
				_('让路 %s').format(fmtNum(s.tag_skip)));

		row(_('流表命中'), fmtNum(s.flow_hit),
			_('未命中 %s / 写入 %s').format(fmtNum(s.flow_miss), fmtNum(s.flow_write)));

		return E('table', { 'class': 'table' }, [ E('tbody', {}, rows) ]);
	}
});
