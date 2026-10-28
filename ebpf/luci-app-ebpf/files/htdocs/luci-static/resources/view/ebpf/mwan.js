'use strict';
'require view';
'require uci';
'require fs';
'require rpc';
'require ui';

/* Network -> 多 WAN 负载: per-flow load balancing across the uplinks that
 * ebpf-mwan owns (routing tables, fwmark rules, dpd_wans, einat).
 *
 * Layout rules for this page:
 *   - the table is the list of uplinks; the WAN interface column is read-only
 *     there, because picking an interface is the one choice that changes which
 *     einat instance / routing table a row owns. It is only editable in the
 *     edit dialog.
 *   - "+ 添加接口" appends a row immediately: creating a row is not destructive,
 *     and asking for confirmation before an empty row exists is just friction.
 *     The row stays inactive until an interface is chosen in the dialog.
 *   - every change is written with uci and applied right away (commit, then
 *     restart ebpf-mwan). There is no page-level Save that can be forgotten.
 *
 * Status comes from /var/run/ebpf-mwan/wans (one line per reconciled uplink:
 * ifn dev mark table pref weight target flags, flags bit 0 = up) and
 * from netifd's device statistics.
 */

var callInterfaces = rpc.declare({
	object: 'network.interface',
	method: 'dump',
	expect: { interface: [] }
});

var callDevices = rpc.declare({
	object: 'network.device',
	method: 'status',
	expect: {}
});

/* rpcd's uci.apply commits the staged changes and fires the config-change
 * triggers (ebpf-mwan's reload trigger is "ebpf_mwan"). rollback=false
 * skips the confirm/rollback flow that LuCI's uci.apply() helper uses and
 * that failed with "no data" (ubus code 5) on this image. */
var callApply = rpc.declare({
	object: 'uci',
	method: 'apply',
	params: [ 'timeout', 'rollback' ]
});

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

return view.extend({
	/* The LuCI view base appends its own Save & Apply footer (ui.changes.apply) for views that inherit handleSaveApply. This page has explicit buttons and applies through the uci RPC, so suppress the inherited footer instead of showing a second button. */
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		var self = this;

		self.ifaces = [];
		self.devstats = {};
		self.runtime = {};

		return Promise.all([
			uci.load('ebpf_mwan'),
			uci.load('network'),
			callInterfaces().catch(function() { return []; }),
			callDevices().catch(function() { return {}; }),
			fs.read('/var/run/ebpf-mwan/wans').catch(function() { return ''; })
		]).then(function(res) {
			self.ifaces = res[2] || [];
			self.devstats = res[3] || {};
			self.parseRuntime(res[4] || '');
		});
	},

	parseRuntime: function(text) {
		var self = this;

		self.runtime = {};

		text.split('\n').forEach(function(line) {
			var f = line.trim().split(/\s+/);

			if (f.length >= 8)
				self.runtime[f[0]] = {
					dev: f[1],
					weight: parseInt(f[5], 10) || 0,
					flags: parseInt(f[7], 10) || 0
				};
		});
	},

	ifaceChoices: function() {
		var seen = {}, out = [];

		function add(name, label) {
			if (!name || seen[name])
				return;

			seen[name] = true;
			out.push({ value: name, label: label || name });
		}

		/* netifd first: the authoritative logical name, with the l3_device
		 * (pppoe-wan, eth1, ...) as a hint. */
		(this.ifaces || []).forEach(function(iface) {
			if (iface.interface == 'loopback')
				return;

			var dev = iface.l3_device || iface.device || '';
			var label = iface.interface;

			if (dev && dev != iface.interface)
				label += ' (' + dev + ')';
			if (iface.up === false)
				label += ' · ' + _('未连接');

			add(iface.interface, label);
		});

		/* Fall back to /etc/config/network so a WAN that netifd has not
		 * brought up yet can still be selected. */
		uci.sections('network', 'interface', function(sec) {
			if (sec['.name'] != 'loopback')
				add(sec['.name']);
		});

		/* Keep interfaces already in ebpf_mwan selectable. */
		uci.sections('ebpf_mwan', 'wan', function(sec) {
			add(sec.interface);
		});

		add('wan');

		return out;
	},

	row: function(title, control, desc) {
		return E('div', { 'class': 'cbi-value' }, [
			E('label', { 'class': 'cbi-value-title' }, [ title ]),
			E('div', { 'class': 'cbi-value-field' }, [
				control,
				desc ? E('div', { 'class': 'cbi-value-description' }, [ desc ]) : ''
			])
		]);
	},

	render: function() {
		var self = this;

		self.gEnable = E('input', { type: 'checkbox' });
		self.gEnable.checked = uci.get('ebpf_mwan', 'global', 'enabled') == '1';

		self.gInterval = E('input', {
			'class': 'cbi-input-text', type: 'number',
			min: '1', max: '3600',
			value: uci.get('ebpf_mwan', 'global', 'health_interval') || '5'
		});

		self.gMode = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { value: 'auto' }, [ _('按带宽比例自动') ]),
			E('option', { value: 'manual' }, [ _('手动权重') ])
		]);
		self.gMode.value = uci.get('ebpf_mwan', 'global', 'mode') || 'auto';

		self.tbody = E('tbody');

		var table = E('table', { 'class': 'table' }, [
			E('thead', {}, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th' }, [ _('WAN 接口') ]),
					E('th', { 'class': 'th' }, [ _('带宽 (Mbit/s)') ]),
					E('th', { 'class': 'th' }, [ _('权重') ]),
					E('th', { 'class': 'th' }, [ _('启用') ]),
					E('th', { 'class': 'th' }, [ _('状态') ]),
					E('th', { 'class': 'th' }, [ _('操作') ])
				])
			]),
			self.tbody
		]);

		self.renderRows();

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [ _('多 WAN 负载') ]),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('按流把新建连接分配到多条 WAN，每条 WAN 仍由自己的 einat 实例做 NAT。' +
				  '可按带宽比例自动分配，也可手动指定权重；已有连接在重载后重建。')
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('全局') ]),

				self.row(_('启用多 WAN'), self.gEnable,
					_('关闭后恢复单 WAN 行为：清掉 fwmark 规则和 dpd_wans 表。')),

				self.row(_('健康检查间隔'), self.gInterval,
					_('秒（1–3600）。常驻的 health 循环按这个间隔 ping 每条 WAN 的健康目标。')),

				self.row(_('负载方式'), self.gMode,
					_('自动：权重 = 本 WAN 带宽 / 最小带宽（1–8）。手动：直接使用每条 WAN 的“权重”。'))
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('WAN 接口') ]),
				table,
				E('div', { 'class': 'cbi-section-create' }, [
					E('button', {
						'class': 'cbi-button cbi-button-add',
						click: function() { return self.addUplink(); }
					}, [ _('添加接口') ])
				]),
				E('div', { 'class': 'cbi-value-description' }, [
					_('接口在表格里是锁定的，点“编辑”才能选择。新加的行在选好接口之前不会生效。')
				])
			]),

			/* One save button for the whole page, at the bottom where the
			 * eye lands after filling it in. Row edits apply from the edit
			 * dialog itself, so this button writes the global block. */
			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-apply',
					click: function() { return self.saveGlobal(); }
				}, [ _('保存并应用') ])
			])
		]);
	},

	devOf: function(ifn) {
		var dev = '';

		(this.ifaces || []).forEach(function(iface) {
			if (iface.interface == ifn)
				dev = iface.l3_device || iface.device || '';
		});

		return dev;
	},

	renderRows: function() {
		var self = this;
		var any = false;

		while (self.tbody.firstChild)
			self.tbody.removeChild(self.tbody.firstChild);

		uci.sections('ebpf_mwan', 'wan', function(sec) {
			any = true;
			self.tbody.appendChild(self.renderRow(sec));
		});

		if (!any)
			self.tbody.appendChild(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td', colspan: 6 }, [
					E('em', {}, [ _('还没有接口，点“添加接口”。') ])
				])
			]));
	},

	renderRow: function(sec) {
		var self = this;
		var sid = sec['.name'];
		var ifn = sec.interface || '';
		var on = sec.enabled != '0';
		var rt = ifn ? self.runtime[ifn] : null;
		var dev = (rt && rt.dev) || self.devOf(ifn);
		var label = ifn || _('未选择');

		if (ifn && dev && dev != ifn)
			label += ' (' + dev + ')';

		var status;

		if (!ifn)
			status = _('等待选择接口');
		else if (!on)
			status = _('已停用');
		else if (!rt)
			status = _('未就绪（服务未运行或该 WAN 还没有可用网关）');
		else {
			status = ((rt.flags & 1) ? _('up') : _('down')) + ' · ' + rt.dev +
				' · ' + _('生效权重') + ' ' + rt.weight;

			var stats = (self.devstats[rt.dev] || {}).statistics;

			if (stats)
				status += ' · RX ' + fmtBytes(stats.rx_bytes) +
					' / TX ' + fmtBytes(stats.tx_bytes);
		}

		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, [
				ifn ? label : E('em', { style: 'color:#c44' }, [ label ])
			]),
			E('td', { 'class': 'td' }, [ sec.bandwidth || '—' ]),
			E('td', { 'class': 'td' }, [ sec.weight || '1' ]),
			E('td', { 'class': 'td' }, [ on ? '✓' : '✗' ]),
			E('td', { 'class': 'td' }, [ status ]),
			E('td', { 'class': 'td' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-edit',
					click: function() { return self.editUplink(sid); }
				}, [ _('编辑') ]),
				' ',
				E('button', {
					'class': 'btn cbi-button cbi-button-remove',
					click: function() { return self.removeUplink(sid); }
				}, [ _('删除') ])
			])
		]);
	},

	applyChanges: function(cmds, opts) {
		var self = this;

		opts = opts || {};

		/* Stage through the LuCI uci RPC, not /sbin/uci: the RPC is the path
		 * the page ACL covers (write.uci ebpf_mwan), while fs.exec would
		 * need a shell command whitelist and was rejected with "no permission".
		 *
		 * Command shapes from the callers:
		 *   [set, ebpf_mwan, <name>, <type>]        create a section
		 *   [set, ebpf_mwan, <sid>, <opt>, <val>]   set an option
		 *   [delete, ebpf_mwan, <sid>, <opt>]       unset an option
		 *   [delete, ebpf_mwan, <sid>]              remove a section
		 */
		(cmds || []).forEach(function(args) {
			var op = args[0];

			if (op == 'set' && args.length == 4) {
				uci.add('ebpf_mwan', args[3], args[2]);
			}
			else if (op == 'set') {
				uci.set('ebpf_mwan', args[2], args[3], args[4]);
			}
			else if (op == 'delete' && args.length == 4) {
				if (uci.get('ebpf_mwan', args[2], args[3]) !== undefined)
					uci.unset('ebpf_mwan', args[2], args[3]);
			}
			else if (op == 'delete') {
				uci.remove('ebpf_mwan', args[2]);
			}
		});

		return uci.save().then(function() {
			/* Commit + config-change triggers (this also reloads
			 * ebpf-mwan, whose procd trigger names ebpf_mwan).
			 * rollback=false: LuCI's uci.apply() helper polls confirm
			 * for ten seconds, which made the dialog feel stuck. */
			return callApply(0, false);
		}).then(function() { return self.reload(); })
		.then(function() {
			if (opts.closeModal)
				ui.hideModal();
			if (opts.notify)
				ui.addNotification(null, E('p', {}, [ opts.notify ]), 'info');

			/* The restart runs in the background; refresh the status
			 * column once it has had time to reconcile. */
			window.setTimeout(function() {
				self.reload().catch(function() {});
			}, 5000);
		})
		.catch(function(e) {
			ui.addNotification(null, E('p', {}, [ e.message || String(e) ]), 'danger');
		});
	},
	reload: function() {
		var self = this;

		uci.unload([ 'ebpf_mwan' ]);

		return uci.load('ebpf_mwan').then(function() {
			return fs.read('/var/run/ebpf-mwan/wans').catch(function() { return ''; });
		}).then(function(text) {
			self.parseRuntime(text || '');
			self.renderRows();
		});
	},

	saveGlobal: function() {
		var self = this;
		var iv = String(self.gInterval.value).trim();

		if (!/^[0-9]+$/.test(iv) || parseInt(iv, 10) < 1 || parseInt(iv, 10) > 3600)
			return ui.addNotification(null, E('p', {}, [
				_('健康检查间隔必须是 1–3600 的整数秒')
			]), 'danger');

		return self.applyChanges([
			[ 'set', 'ebpf_mwan', 'global', 'enabled', self.gEnable.checked ? '1' : '0' ],
			[ 'set', 'ebpf_mwan', 'global', 'health_interval', String(parseInt(iv, 10)) ],
			[ 'set', 'ebpf_mwan', 'global', 'mode', self.gMode.value ]
		], { notify: _('已保存并应用') });
	},

	addUplink: function() {
		var self = this;
		var used = {}, n = 1, name;

		uci.sections('ebpf_mwan', 'wan', function(sec) {
			used[sec['.name']] = true;
		});

		do {
			name = (n == 1) ? 'wan' : 'wan' + n;
			n++;
		} while (used[name]);

		/* No dialog: the row appears at once and is inactive until an
		 * interface is chosen here. */
		return self.applyChanges([
			[ 'set', 'ebpf_mwan', name, 'wan' ],
			[ 'set', 'ebpf_mwan', name, 'enabled', '1' ],
			[ 'set', 'ebpf_mwan', name, 'weight', '1' ]
		], { notify: _('已添加接口行，点“编辑”选择 WAN 接口') });
	},

	removeUplink: function(sid) {
		var self = this;
		var ifn = uci.get('ebpf_mwan', sid, 'interface') || sid;

		ui.showModal(_('删除接口'), [
			E('p', {}, [ _('把 “%s” 从负载均衡里删除？').format(ifn) ]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn cbi-button', click: function() { ui.hideModal(); } }, [ _('取消') ]),
				' ',
				E('button', {
					'class': 'btn cbi-button cbi-button-negative important',
					click: function() {
						return self.applyChanges([
							[ 'delete', 'ebpf_mwan', sid ]
						], { closeModal: true, notify: _('已删除') });
					}
				}, [ _('删除') ])
			])
		], 'cbi-modal');
	},

	editUplink: function(sid) {
		var self = this;
		var cur = uci.get('ebpf_mwan', sid, 'interface') || '';

		var sel = E('select', { 'class': 'cbi-input-select' });

		self.ifaceChoices().forEach(function(c) {
			sel.appendChild(E('option', { value: c.value }, [ c.label ]));
		});
		sel.value = cur;

		var bw = E('input', {
			'class': 'cbi-input-text', type: 'number',
			min: '1', max: '100000', placeholder: '100',
			value: uci.get('ebpf_mwan', sid, 'bandwidth') || ''
		});

		var wt = E('input', {
			'class': 'cbi-input-text', type: 'number',
			min: '1', max: '8', placeholder: '1',
			value: uci.get('ebpf_mwan', sid, 'weight') || '1'
		});

		var on = E('input', { type: 'checkbox' });
		on.checked = uci.get('ebpf_mwan', sid, 'enabled') != '0';

		var hl = E('input', {
			'class': 'cbi-input-text',
			placeholder: _('缺省用网关'),
			value: uci.get('ebpf_mwan', sid, 'health') || ''
		});

		function save() {
			var ifn = sel.value;
			var b = String(bw.value).trim();
			var w = String(wt.value).trim();
			var h = String(hl.value).trim();
			var dup = null;
			var cmds;

			if (!ifn)
				return ui.addNotification(null, E('p', {}, [ _('请选择 WAN 接口') ]), 'danger');

			/* One uplink, one row: two rows on the same interface would each
			 * get their own einat instance and fwmark table. */
			uci.sections('ebpf_mwan', 'wan', function(sec) {
				if (sec['.name'] != sid && (sec.interface || '') == ifn)
					dup = sec['.name'];
			});

			if (dup)
				return ui.addNotification(null, E('p', {}, [
					_('接口 %s 已经被另一行使用（%s）').format(ifn, dup)
				]), 'danger');

			if (!/^[1-8]$/.test(w))
				return ui.addNotification(null, E('p', {}, [ _('权重必须是 1–8 的整数') ]), 'danger');
			if (b !== '' && (!/^[0-9]+$/.test(b) || parseInt(b, 10) < 1 || parseInt(b, 10) > 100000))
				return ui.addNotification(null, E('p', {}, [ _('带宽必须是 1–100000 的整数（Mbit/s），或留空') ]), 'danger');
			if (h !== '' && !/^[0-9A-Za-z._:-]+$/.test(h))
				return ui.addNotification(null, E('p', {}, [ _('健康目标只能是 IP 或主机名') ]), 'danger');

			cmds = [
				[ 'set', 'ebpf_mwan', sid, 'interface', ifn ],
				[ 'set', 'ebpf_mwan', sid, 'enabled', on.checked ? '1' : '0' ],
				[ 'set', 'ebpf_mwan', sid, 'weight', String(parseInt(w, 10)) ],
				b === '' ? [ 'delete', 'ebpf_mwan', sid, 'bandwidth' ]
				         : [ 'set', 'ebpf_mwan', sid, 'bandwidth', b ],
				h === '' ? [ 'delete', 'ebpf_mwan', sid, 'health' ]
				         : [ 'set', 'ebpf_mwan', sid, 'health', h ]
			];

			return self.applyChanges(cmds, { closeModal: true, notify: _('已保存并应用') });
		}

		ui.showModal(_('编辑接口'), [
			self.row(_('WAN 接口'), sel,
				_('逻辑接口（wan / wan2 / pppoe-wan …）。只能在编辑里选择。')),
			self.row(_('带宽 (Mbit/s)'), bw,
				_('“按带宽比例自动”时使用；手动模式忽略。')),
			self.row(_('权重'), wt,
				_('1–8，仅“手动权重”模式使用。')),
			self.row(_('启用'), on,
				_('关闭后这条 WAN 不参与负载均衡。')),
			self.row(_('健康目标'), hl,
				_('从这条 WAN 发 ping 的地址；留空则用 netifd 报告的网关。')),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn cbi-button', click: function() { ui.hideModal(); } }, [ _('取消') ]),
				' ',
				E('button', {
					'class': 'btn cbi-button cbi-button-positive important',
					click: save
				}, [ _('保存') ])
			])
		], 'cbi-modal');
	}
});
