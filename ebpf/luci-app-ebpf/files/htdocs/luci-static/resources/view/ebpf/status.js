'use strict';
'require view';
'require fs';
'require rpc';
'require ui';

/* Network -> 加速状态: what the eBPF fast path is doing right now.
 *
 * Where the numbers come from, in order of preference:
 *
 *   1. `dpdctl status -j` over rpcd's file.exec. This is the live source:
 *      the tool reads the pinned maps directly, so the counters are current.
 *   2. /var/run/ebpf/status.json, which dpd-gate-watchdog rewrites on every
 *      tick (20 s). Used when exec is not permitted for this ACL, so the page
 *      still works on a stock rpcd -- just up to one interval behind.
 *   3. /var/run/ebpf/gate.json, always read: the gate is the one thing the
 *      watchdog publishes the moment it changes, and explaining *why* the
 *      datapath is not accelerating matters more than a perfect counter.
 *
 * The page polls every 2 s while it is open and computes the rates itself
 * from the cumulative counters (bytes/pkt_total), so there is no daemon
 * sampling for the UI and no extra state on the router.
 */

var callExec = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params' ],
	expect: { stdout: '' }
});

var STAT_LABELS = {
	pkt_total:    [ '进入程序的包', '每一包都先计数' ],
	bytes:        [ '进入程序的字节', '' ],
	non_ip:       [ '非 IP', 'ARP / PPPoE 控制帧等' ],
	fib_ok:       [ '路由查找成功', 'bpf_fib_lookup -> SUCCESS' ],
	fib_fail:     [ '路由查找失败', '不可转发 / 无路由 / 需要分片' ],
	fib_retry:    [ '路由重试', 'PPP/tunnel 无邻居表，二次查找' ],
	redirect_ok:  [ 'bpf_redirect 成功', 'L2 头已自行写好' ],
	neigh_ok:     [ 'redirect_neigh 已受理', '仅代表请求被接受，不代表送达' ],
	neigh_fail:   [ 'redirect_neigh 失败', '退回协议栈' ],
	flow_hit:     [ '流表命中', '已被接管的包' ],
	flow_miss:    [ '流表未命中', '每流第一包，走协议栈' ],
	flow_write:   [ '流表写入', '' ],
	ttl_drop:     [ 'TTL 耗尽丢弃', '' ],
	local:        [ '本机目的', '不接管' ],
	v6_skip:      [ 'IPv6 跳过', 'ipv6 关或包不合规' ],
	v6_ok:        [ 'IPv6 已接管', '' ],
	vlan_skip:    [ 'VLAN 策略跳过', 'vlans_only 下不在名单里' ],
	frag_skip:    [ '分片跳过', '' ],
	dns_skip:     [ 'DNS 跳过', ':53 留给 dns_redirect/SmartDNS' ],
	dhcp_skip:    [ 'DHCP 跳过', '必须留给本机服务' ],
	bcast_skip:   [ '广播/组播跳过', '' ],
	mss_clamp:    [ 'MSS 已改写', 'SYN/SYN-ACK 按出口 MTU 收窄' ],
	mss_skip:     [ 'MSS 未改写', '出口 MTU 未知或低于 536' ]
};

function fmtBytes(n) {
	n = parseInt(n, 10) || 0;

	var unit = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB' ];
	var i = 0;

	while (n >= 1024 && i < unit.length - 1) {
		n /= 1024;
		i++;
	}

	return (i ? n.toFixed(1) : String(n)) + ' ' + unit[i];
}

function fmtBitRate(bps) {
	bps = Number(bps) || 0;

	if (bps >= 1e9)
		return (bps / 1e9).toFixed(2) + ' Gbit/s';
	if (bps >= 1e6)
		return (bps / 1e6).toFixed(1) + ' Mbit/s';
	if (bps >= 1e3)
		return (bps / 1e3).toFixed(0) + ' kbit/s';

	return bps.toFixed(0) + ' bit/s';
}

function fmtNum(n) {
	return (Number(n) || 0).toLocaleString();
}

function parseJSON(text) {
	try {
		var v = JSON.parse(text);

		return (v && typeof v === 'object') ? v : null;
	}
	catch (e) {
		return null;
	}
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		var self = this;

		self.status = null;
		self.gate = null;
		self.source = 'none';
		self.err = null;
		self.sample = null;

		return self.refresh().catch(function(e) {
			self.err = e.message || String(e);
		});
	},

	/* One fetch cycle. Returns the object that was rendered. */
	refresh: function() {
		var self = this;

		function readGate() {
			return fs.read('/var/run/ebpf/gate.json').then(parseJSON)
				.catch(function() { return null; });
		}

		return callExec('/usr/sbin/dpdctl', [ 'status', '-j' ])
			.then(function(res) {
				var st = parseJSON(res && res.stdout);

				if (!st)
					throw new Error('dpdctl status -j: bad JSON');

				self.status = st;
				self.source = 'dpdctl';
				return readGate();
			})
			.catch(function() {
				return fs.read('/var/run/ebpf/status.json')
					.then(function(text) {
						var st = parseJSON(text);

						if (!st)
							throw new Error('no status.json');

						self.status = st;
						self.source = 'status.json';
						return readGate();
					});
			})
			.then(function(gate) {
				self.gate = gate || (self.status && self.status.gate) || null;
				self.err = null;
				self.tick();
			})
			.catch(function(e) {
				self.err = e.message || String(e);
			})
			.then(function() {
				self.renderBody();
			});
	},

	/* Rates from cumulative counters: keep the previous sample and divide. */
	tick: function() {
		var self = this;
		var st = self.status && self.status.stats;

		if (!st)
			return;

		var now = Date.now();
		var cur = {
			t: now,
			bytes: Number(st.bytes) || 0,
			pkts: Number(st.pkt_total) || 0,
			hit: Number(st.flow_hit) || 0
		};

		if (self.sample && now > self.sample.t) {
			var dt = (now - self.sample.t) / 1000;

			cur.bps = (cur.bytes - self.sample.bytes) * 8 / dt;
			cur.pps = (cur.pkts - self.sample.pkts) / dt;
			cur.hit_pps = (cur.hit - self.sample.hit) / dt;
		}

		self.sample = cur;
	},

	modeBadge: function(cfg) {
		var mode = cfg ? cfg.mode : '?';
		var cls = (mode == 'stateful' || mode == 'stateless') ? 'label success'
			: (mode == 'observe') ? 'label warning'
			: 'label';

		return E('span', { 'class': cls }, [ mode ]);
	},

	gateBanner: function() {
		var self = this;
		var g = self.gate;
		var st = self.status;

		if (!g) {
			return E('div', { 'class': 'alert-message warning' }, [
				E('strong', {}, [ _('还没有判定结果') ]),
				E('br'),
				E('span', {}, [ _('运行 /usr/libexec/dpd-gate-refresh 或重启 dpd-fastpath 后会写入 /var/run/ebpf/gate.json。') ])
			]);
		}

		var ok = (g.code == 'ok');
		var cls = ok ? 'alert-message success' : 'alert-message warning';

		return E('div', { 'class': cls }, [
			E('strong', {}, [
				ok ? _('加速已启用') : _('加速未启用（降级为 observe）')
			]),
			E('span', { 'class': 'label' }, [ ' ' + (g.effective || '?') ]),
			E('br'),
			E('span', {}, [
				_('原因：'), E('code', {}, [ g.code || '?' ]), ' — ',
				E('span', {}, [ g.reason || '' ])
			]),
			g.at ? E('div', { 'class': 'cbi-value-description' }, [
				_('判定时间 %s，已开机 %s 秒').format(g.at, g.uptime_s != null ? g.uptime_s : '?')
			]) : ''
		]);
	},

	checksTable: function() {
		var c = (this.gate && this.gate.checks) || null;

		if (!c)
			return E('div', { 'class': 'cbi-value-description' }, [
				_('该 gate.json 没有 checks 字段（旧版本写入的）。')
			]);

		function row(label, v, hint) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, [ label ]),
				E('td', { 'class': 'td' }, [
					E('span', { 'class': v ? 'label success' : 'label warning' },
						[ v ? _('是') : _('否') ])
				]),
				E('td', { 'class': 'td' }, [ hint || '' ])
			]);
		}

		return E('table', { 'class': 'table' }, [
			E('thead', {}, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th' }, [ _('判定输入') ]),
					E('th', { 'class': 'th' }, [ _('满足') ]),
					E('th', { 'class': 'th' }, [ _('说明') ])
				])
			]),
			E('tbody', {}, [
				row(_('有可用上行'), !!c.uplink, _('存在 WAN 设备且有默认路由')),
				row(_('einat 已挂载'), !!c.einat, _('eBPF NAT 是加速的前提（回程靠它）')),
				row(_('einat 在每条上行上'), !!c.einat_on_uplink, _('任一上行缺 einat 都会否决')),
				row(_('honk 占用 TCX'), !!c.honk, _('代理在 TCX 上先于所有经典过滤器')),
				row(_('honk 是 p1 核心'), !!c.honk_p1, _('/usr/share/honk/direct-unspec 存在'))
			])
		]);
	},

	cards: function() {
		var st = (this.status && this.status.stats) || {};
		var cfg = (this.status && this.status.cfg) || {};
		var mp = (this.status && this.status.maps) || {};
		var s = this.sample || {};

		function card(title, value, hint) {
			return E('div', { 'class': 'cbi-section', 'style': 'flex:1 1 180px;margin:0 8px 8px 0;min-width:180px' }, [
				E('div', { 'class': 'cbi-value-description' }, [ title ]),
				E('div', { 'style': 'font-size:1.5em;line-height:1.4' }, [ value ]),
				hint ? E('div', { 'class': 'cbi-value-description' }, [ hint ]) : ''
			]);
		}

		return E('div', { 'style': 'display:flex;flex-wrap:wrap' }, [
			card(_('当前模式'), this.modeBadge(cfg),
				_('请求 %s · 策略 %s').format(cfg.mode || '?', cfg.policy || '?')),
			card(_('实时吞吐'), fmtBitRate(s.bps || 0),
				_('按进入程序的字节计（含未接管的包）')),
			card(_('包速率'), fmtNum(Math.round(s.pps || 0)) + ' pps',
				_('接管速率 %s pps').format(fmtNum(Math.round(s.hit_pps || 0)))),
			card(_('已接管包'), fmtNum(st.flow_hit || 0),
				_('字节 %s').format(fmtBytes(st.bytes || 0))),
			card(_('流表容量'), fmtNum((mp.flows && mp.flows.max_entries) || 0),
				_('LRU hash，满后自动淘汰最久未用')),
			card(_('MSS 改写'), fmtNum(st.mss_clamp || 0),
				_('未改写 %s 次').format(fmtNum(st.mss_skip || 0)))
		]);
	},

	statsTable: function() {
		var st = (this.status && this.status.stats) || {};
		var self = this;
		var order = Object.keys(STAT_LABELS).filter(function(k) { return st[k] != null; });

		if (!order.length)
			return E('div', { 'class': 'cbi-value-description' }, [ _('没有计数器（程序未加载？）') ]);

		return E('table', { 'class': 'table' }, [
			E('thead', {}, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th' }, [ _('计数器') ]),
					E('th', { 'class': 'th' }, [ _('累计') ]),
					E('th', { 'class': 'th' }, [ _('说明') ])
				])
			]),
			E('tbody', {}, order.map(function(k) {
				var lab = STAT_LABELS[k];

				return E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td' }, [ E('code', {}, [ k ]), ' ', lab[0] ]),
					E('td', { 'class': 'td' }, [ fmtNum(st[k]) ]),
					E('td', { 'class': 'td' }, [ lab[1] || '' ])
				]);
			}))
		]);
	},

	ifacesTable: function() {
		var list = (this.status && this.status.ifaces) || [];

		if (!list.length)
			return E('div', { 'class': 'cbi-value-description' }, [ _('没有已登记接口。') ]);

		return E('table', { 'class': 'table' }, [
			E('thead', {}, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th' }, [ _('设备') ]),
					E('th', { 'class': 'th' }, [ _('ifindex') ]),
					E('th', { 'class': 'th' }, [ _('MTU') ]),
					E('th', { 'class': 'th' }, [ _('标志') ])
				])
			]),
			E('tbody', {}, list.map(function(i) {
				return E('tr', { 'class': 'tr' }, [
					E('td', { 'class': 'td' }, [ i.name ]),
					E('td', { 'class': 'td' }, [ String(i.ifindex) ]),
					E('td', { 'class': 'td' }, [ String(i.mtu || '?') ]),
					E('td', { 'class': 'td' }, [ i.flags || '' ])
				]);
			}))
		]);
	},

	wansTable: function() {
		var list = (this.status && this.status.wans) || [];

		if (!list.length)
			return '';

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ _('多 WAN 上行') ]),
			E('table', { 'class': 'table' }, [
				E('thead', {}, [
					E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th' }, [ _('#') ]),
						E('th', { 'class': 'th' }, [ _('设备') ]),
						E('th', { 'class': 'th' }, [ _('权重') ]),
						E('th', { 'class': 'th' }, [ _('fwmark') ]),
						E('th', { 'class': 'th' }, [ _('状态') ])
					])
				]),
				E('tbody', {}, list.map(function(w) {
					return E('tr', { 'class': 'tr' }, [
						E('td', { 'class': 'td' }, [ String(w.index) ]),
						E('td', { 'class': 'td' }, [ w.ifname ]),
						E('td', { 'class': 'td' }, [ String(w.weight) ]),
						E('td', { 'class': 'td' }, [ '0x' + Number(w.mark || 0).toString(16) ]),
						E('td', { 'class': 'td' }, [
							E('span', { 'class': w.up ? 'label success' : 'label warning' },
								[ w.up ? _('up') : _('down') ])
						])
					]);
				}))
			])
		]);
	},

	renderBody: function() {
		var self = this;
		var root = document.getElementById('ebpf-accel-body');

		if (!root)
			return;

		while (root.firstChild)
			root.removeChild(root.firstChild);

		if (self.err && !self.status) {
			root.appendChild(E('div', { 'class': 'alert-message danger' }, [
				E('strong', {}, [ _('读取状态失败') ]),
				E('br'),
				E('span', {}, [ self.err ])
			]));

			return;
		}

		root.appendChild(self.gateBanner());
		root.appendChild(self.cards());

		var st = self.status || {};
		var meta = E('div', { 'class': 'cbi-value-description' }, [
			_('数据源：%s · 程序 ABI %s · 已加载 ABI %s · 采样 %s')
				.format(self.source, st.abi != null ? st.abi : '?',
					st.loaded_abi != null ? st.loaded_abi : '?',
					new Date().toLocaleTimeString())
		]);

		root.appendChild(meta);

		root.appendChild(E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ _('判定依据') ]),
			self.checksTable()
		]));

		root.appendChild(E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ _('计数器') ]),
			self.statsTable()
		]));

		root.appendChild(E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ _('加速接口') ]),
			self.ifacesTable()
		]));

		root.appendChild(self.wansTable());
	},

	render: function() {
		var self = this;

		/* The interval outlives the view if the user navigates away: stop it
		 * as soon as the container it renders into is gone, otherwise every
		 * page change leaves a 2-second rpcd poll behind. */
		self.timer = window.setInterval(function() {
			if (!document.getElementById('ebpf-accel-body')) {
				window.clearInterval(self.timer);
				return;
			}
			self.refresh().catch(function() {});
		}, 2000);

		/* load() ran before the container existed, so the first paint is the
		 * placeholder; fetch once now that it is in the DOM. */
		window.setTimeout(function() { self.refresh().catch(function() {}); }, 0);

		return E([], [
			E('h2', {}, [ _('加速状态') ]),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('eBPF 快速路径（dpd-fastpath）的实时状态：是否被 gate 降级、' +
				  '接管了多少包、各计数器的去向。数据每 2 秒刷新一次。')
			]),
			E('div', { 'id': 'ebpf-accel-body' }, [
				E('div', { 'class': 'cbi-value-description' }, [ _('读取中…') ])
			]),
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', {
					'class': 'btn cbi-button',
					click: function() { return self.refresh(); }
				}, [ _('立即刷新') ])
			])
		]);
	}
});
