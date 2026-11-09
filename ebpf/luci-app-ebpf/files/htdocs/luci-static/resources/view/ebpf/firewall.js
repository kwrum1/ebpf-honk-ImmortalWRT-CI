'use strict';
'require view';
'require uci';
'require rpc';
'require ui';

/* rpcd's uci.apply commits the session's staged changes and fires the
 * config-change triggers (fw4 and the ACL guard reload themselves). It is
 * called with rollback=false: LuCI's own uci.apply() helper asks for the
 * rollback flow and then polls uci.confirm for up to ten seconds, which on
 * this image fails with "no data" (ubus code 5). */
var callApply = rpc.declare({
	object: 'uci',
	method: 'apply',
	params: [ 'timeout', 'rollback' ]
});

/* Network -> 简易防火墙: one WAN port list for IPv4 and IPv6.
 *
 * Two row kinds, chosen by the "目标" column:
 *   - empty or 路由器 -> config rule, src=wan, target=ACCEPT. This lets the
 *     port through to the router itself (INPUT).
 *   - an IPv4/IPv6 address -> config redirect, src=wan, dest=lan,
 *     target=DNAT. This forwards the port to a host behind the router.
 *
 * Why this is a hand-rolled table instead of form.GridSection:
 *   - GridSection's "+" always opens LuCI's "more options" modal, even when
 *     every option is inline (modalonly=false). With no modal-only field the
 *     dialog is an empty "Save / Dismiss" box -- exactly the extra click that
 *     made "添加" feel broken.
 *   - The old save path only called uci.save() (writes the config delta) and
 *     then reloaded fw4. fw4 reads /etc/config, so the row did not actually
 *     apply until something else committed it. Here every Save stages the
 *     rows through the LuCI uci RPC, then uci apply commits the session's
 *     delta and fires the config-change triggers (fw4 reload, and the ACL
 *     guard re-imports the port list).
 *
 * Ownership: every section this page creates gets the name prefix
 * 'dpd-simple: '. The old dpd_simple option is accepted for migration but is
 * removed on save -- fw4 logs unknown options and does not apply those
 * sections, which is why an earlier version's rows silently never opened a
 * port. collect() also shows legacy WAN->LAN DNAT redirects and adopts them.
 *
 * A default-deny WAN is required for "only these ports are open" to be true.
 * The page checks it but never changes it on its own: a visible warning and
 * an explicit "设为默认拒绝" button are supplied instead.
 */

var MARKER = 'dpd-simple: ';

function isOwned(sec) {
	return uciVal(sec.name).indexOf(MARKER) == 0 ||
		uciVal(sec.dpd_simple) == '1';
}

function displayName(n) {
	return uciVal(n).replace(/^dpd-simple:\s*/, '');
}

function uciVal(v) {
	if (v == null)
		return '';

	return Array.isArray(v) ? v.join(' ') : String(v);
}

function trim(v) {
	return uciVal(v).trim();
}

function uciProto(v) {
	v = trim(v);

	if (v == '')
		return 'tcp';

	return v.split(/\s+/).sort().join(' ');
}

function uciFamily(v) {
	v = trim(v);

	return (v == 'ipv4' || v == 'ipv6') ? v : 'any';
}

function validIPv4(v) {
	var parts = v.split('.');

	if (parts.length != 4)
		return false;

	for (var i = 0; i < 4; i++) {
		if (!/^(0|[1-9][0-9]{0,2})$/.test(parts[i]))
			return false;
		if (parseInt(parts[i], 10) > 255)
			return false;
	}

	return true;
}

function validIPv6(v) {
	if (v.indexOf(':') < 0 || !/^[0-9a-fA-F:.]+$/.test(v))
		return false;

	var halves = v.split('::');

	if (halves.length > 2)
		return false;

	var head = (halves[0] === '') ? [] : halves[0].split(':');
	var tail = (halves.length == 2 && halves[1] !== '') ? halves[1].split(':') : [];
	var lists = [ head, tail ];
	var groups = 0;

	for (var i = 0; i < lists.length; i++) {
		for (var j = 0; j < lists[i].length; j++) {
			var g = lists[i][j];

			if (g === '')
				return false;

			/* An embedded IPv4 address is only valid as the final group. */
			if (i == lists.length - 1 && j == lists[i].length - 1 &&
			    g.indexOf('.') >= 0) {
				if (!validIPv4(g))
					return false;
				groups += 2;
			}
			else {
				if (!/^[0-9a-fA-F]{1,4}$/.test(g))
					return false;
				groups++;
			}
		}
	}

	return (halves.length == 2) ? (groups <= 7) : (groups == 8);
}

function ipFamily(v) {
	if (validIPv4(v))
		return 4;

	if (validIPv6(v))
		return 6;

	return 0;
}

function isDeny(v) {
	v = trim(v).toUpperCase();

	return (v == 'REJECT' || v == 'DROP');
}

function isAccept(v) {
	return trim(v).toUpperCase() == 'ACCEPT';
}

return view.extend({
	/* The LuCI view base class appends its own Save & Apply footer for every
	 * view that inherits handleSaveApply(). That footer calls
	 * ui.changes.apply() (the ubus/ACL path); this page has its own explicit
	 * button that stages through the uci RPC, so the extra button was both a
	 * duplicate and the source of the "no permission" error. Shadow the three
	 * handlers with null so the base footer is not rendered; the explicit
	 * button below the table is the only one. */
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		var self = this;

		self.rows = [];
		self.removed = [];
		self.def = null;
		self.defaultDeny = false;

		return uci.load('firewall').then(function() {
			self.collect();
		});
	},

	collect: function() {
		var self = this;

		self.rows = [];
		self.removed = [];

		/* UCI sections created by this page. The marker is the contract:
		 * a section without it is someone else's rule. */
		uci.sections('firewall', 'rule', function(sec) {
			if (!isOwned(sec))
				return;

			self.rows.push({
				sid: sec['.name'],
				secType: 'rule',
				legacy: false,
				name: displayName(sec.name),
				target: uciVal(sec.dest_ip),
				public_port: '',
				dest_port: uciVal(sec.dest_port),
				proto: uciProto(sec.proto),
				family: uciFamily(sec.family),
				enabled: uciVal(sec.enabled) != '0'
			});
		});

		uci.sections('firewall', 'redirect', function(sec) {
			var owned = isOwned(sec);
			var src = trim(sec.src);
			var dest = trim(sec.dest);
			var target = trim(sec.target);

			/* Migration: show WAN->LAN DNAT redirects written by the old
			 * page (or by hand). They are adopted on the next save by
			 * setting the marker. Everything else is left alone. */
			if (!owned) {
				if (src != 'wan' || dest != 'lan' || target != 'DNAT')
					return;
				if (trim(sec.dest_ip) == '')
					return;
			}

			self.rows.push({
				sid: sec['.name'],
				secType: 'redirect',
				legacy: !owned,
				name: displayName(sec.name),
				target: uciVal(sec.dest_ip),
				public_port: uciVal(sec.src_dport),
				dest_port: uciVal(sec.dest_port),
				proto: uciProto(sec.proto),
				family: uciFamily(sec.family),
				enabled: uciVal(sec.enabled) != '0'
			});
		});

		self.checkDefaultDeny();
	},

	checkDefaultDeny: function() {
		var self = this;
		var def = {
			defaultsSid: null,
			defaults: {},
			wanSid: null,
			wan: {}
		};

		uci.sections('firewall', 'defaults', function(sec) {
			if (!def.defaultsSid) {
				def.defaultsSid = sec['.name'];
				def.defaults = sec;
			}
		});

		uci.sections('firewall', 'zone', function(sec) {
			if (trim(sec.name) == 'wan' && !def.wanSid) {
				def.wanSid = sec['.name'];
				def.wan = sec;
			}
		});

		def.defaultsOk = (def.defaultsSid != null) &&
			isDeny(def.defaults.input) && isDeny(def.defaults.forward);
		def.wanMissing = (def.wanSid == null);
		def.wanOk = !def.wanMissing &&
			!isAccept(def.wan.input) && !isAccept(def.wan.forward);

		self.def = def;
		self.defaultDeny = def.defaultsOk && def.wanOk;
	},

	render: function() {
		var self = this;

		self.tbody = E('tbody');
		self.warnBox = E('div');

		self.renderRows();
		self.renderWarning();

		var table = E('table', { 'class': 'table' }, [
			E('thead', {}, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th' }, [ _('名称') ]),
					E('th', { 'class': 'th' }, [ _('目标') ]),
					E('th', { 'class': 'th' }, [ _('目标端口') ]),
					E('th', { 'class': 'th' }, [ _('公网端口') ]),
					E('th', { 'class': 'th' }, [ _('协议') ]),
					E('th', { 'class': 'th' }, [ _('地址族') ]),
					E('th', { 'class': 'th' }, [ _('启用') ]),
					E('th', { 'class': 'th' }, [ _('操作') ])
				])
			]),
			self.tbody
		]);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [ _('简易防火墙') ]),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('默认拒绝 WAN 入站（v4+v6），只放行下面列出的端口；' +
				  '目标留空=放行到路由器，填 IP=转发到内网主机。'),
				E('br'),
				_('端口支持单个、范围（8000-8010）和空格分隔的多个值；' +
				  '“目标端口”是内网主机上的服务端口，“公网端口”是 WAN 侧暴露的端口；' +
				  '公网端口留空时默认与目标端口一致。目标是 IPv6 且两个端口相同时，' +
				  '只加转发放行，不做地址转换。')
			]),

			self.warnBox,

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('WAN 端口') ]),
				table,
				E('div', { 'class': 'cbi-section-create' }, [
					E('button', {
						'class': 'cbi-button cbi-button-add',
						click: function() { return self.addRow(); }
					}, [ _('添加规则') ])
				]),
				E('div', { 'class': 'cbi-value-description' }, [
					_('“添加规则”直接加一行，不弹确认框；填好后点下面的“保存并应用”。' +
					  '“目标”留空或填“路由器”=放行到路由器；填 IP=转发到内网主机。')
				])
			]),

			E('div', { 'class': 'cbi-page-actions' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-apply',
					click: function() { return self.saveAll(); }
				}, [ _('保存并应用') ])
			])
		]);
	},

	renderWarning: function() {
		var self = this;

		if (!self.warnBox)
			return;

		while (self.warnBox.firstChild)
			self.warnBox.removeChild(self.warnBox.firstChild);

		if (self.defaultDeny || !self.def)
			return;

		var reasons = [];

		if (!self.def.defaultsOk)
			reasons.push(_('firewall defaults 的 input/forward 不是 REJECT/DROP'));

		if (self.def.wanMissing)
			reasons.push(_('没有找到 name=wan 的防火墙区域'));
		else if (isAccept(self.def.wan.input) || isAccept(self.def.wan.forward))
			reasons.push(_('WAN 区域的 input/forward 是 ACCEPT'));

		self.warnBox.appendChild(E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, [ _('默认拒绝未生效') ]),
			E('div', { 'class': 'alert-message warning' }, [
				E('p', {}, [
					_('当前防火墙没有对 WAN 入站默认拒绝，' +
					  '下面的端口列表不会限制未列出的端口。')
				]),
				E('p', {}, [ reasons.join('；') ]),
				E('p', {}, [
					_('“设为默认拒绝”会把 defaults 与 WAN 区域的 input/forward 设为 REJECT；' +
					  'output 保持 ACCEPT，其他规则不动。')
				]),
				E('button', {
					'class': 'btn cbi-button cbi-button-negative important',
					click: function() { return self.applyDefaultDeny(); }
				}, [ _('设为默认拒绝') ])
			])
		]));
	},

	applyDefaultDeny: function() {
		var self = this;
		var def = self.def;

		if (!def || !def.defaultsSid) {
			ui.addNotification(null, E('p', {}, [
				_('没有找到 firewall defaults 段，无法设置默认拒绝。')
			]), 'danger');
			return Promise.resolve();
		}

		/* Only input/forward are changed. output stays as configured, and
		 * nothing is touched before the user presses the button. */
		uci.set('firewall', def.defaultsSid, 'input', 'REJECT');
		uci.set('firewall', def.defaultsSid, 'forward', 'REJECT');

		if (def.wanSid) {
			uci.set('firewall', def.wanSid, 'input', 'REJECT');
			uci.set('firewall', def.wanSid, 'forward', 'REJECT');
		}

		return uci.save().then(function() {
			return callApply(0, false);
		}).then(function() {
			return self.reload();
		}).then(function() {
			if (def.wanSid)
				ui.addNotification(null, E('p', {}, [
					_('已设为默认拒绝并应用')
				]), 'info');
			else
				ui.addNotification(null, E('p', {}, [
					_('已设置 defaults 默认拒绝；未找到 WAN 区域，请手动检查。')
				]), 'warning');
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [
				e.message || String(e)
			]), 'danger');
		});
	},

	renderRows: function() {
		var self = this;

		while (self.tbody.firstChild)
			self.tbody.removeChild(self.tbody.firstChild);

		self.rows.forEach(function(row, idx) {
			self.tbody.appendChild(self.renderRow(row, idx));
		});

		if (self.rows.length == 0)
			self.tbody.appendChild(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td', colspan: 8 }, [
					E('em', {}, [ _('还没有规则，点“添加规则”。') ])
				])
			]));
	},

	renderRow: function(row, idx) {
		var self = this;

		function input(value, placeholder, width) {
			var attrs = {
				'class': 'cbi-input-text',
				'value': value || ''
			};

			if (width)
				attrs.style = 'width:' + width;
			if (placeholder)
				attrs.placeholder = placeholder;

			return E('input', attrs);
		}

		function select(options, value) {
			var el = E('select', { 'class': 'cbi-input-select' });

			options.forEach(function(o) {
				el.appendChild(E('option', { 'value': o.value }, [ o.label ]));
			});
			el.value = value;

			return el;
		}

		row.elName = input(row.name, _('可选'), '8em');
		row.elTarget = input(row.target, _('留空=路由器 / 填 IP=转发'), '13em');
		row.elDestPort = input(row.dest_port, '8080 / 8000-8010', '10em');
		row.elPublic = input(row.public_port, _('留空=同目标端口'), '10em');

		var protos = [ 'tcp', 'udp', 'tcp udp' ];

		if (protos.indexOf(row.proto) < 0)
			protos.push(row.proto);

		row.elProto = select(protos.map(function(p) {
			var label = (p == 'tcp') ? 'TCP' :
				(p == 'udp') ? 'UDP' :
				(p == 'tcp udp') ? 'TCP+UDP' : p;

			return { value: p, label: label };
		}), row.proto);

		var fams = [
			{ value: 'any', label: _('任意（v4+v6）') },
			{ value: 'ipv4', label: 'IPv4' },
			{ value: 'ipv6', label: 'IPv6' }
		];

		row.elFamily = select(fams, row.family);

		row.elEnabled = E('input', { 'type': 'checkbox' });
		row.elEnabled.checked = row.enabled;

		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, [ row.elName ]),
			E('td', { 'class': 'td' }, [ row.elTarget ]),
			E('td', { 'class': 'td' }, [ row.elDestPort ]),
			E('td', { 'class': 'td' }, [ row.elPublic ]),
			E('td', { 'class': 'td' }, [ row.elProto ]),
			E('td', { 'class': 'td' }, [ row.elFamily ]),
			E('td', { 'class': 'td' }, [ row.elEnabled ]),
			E('td', { 'class': 'td' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-remove',
					click: function() { return self.removeRow(idx); }
				}, [ _('删除') ])
			])
		]);
	},

	addRow: function() {
		this.readAll();

		this.rows.push({
			sid: null,
			secType: null,
			legacy: false,
			name: '',
			target: '',
			public_port: '',
			dest_port: '',
			proto: 'tcp',
			family: 'any',
			enabled: true
		});
		this.renderRows();

		return Promise.resolve();
	},

	removeRow: function(idx) {
		var self = this;

		self.readAll();

		if (idx < 0 || idx >= self.rows.length)
			return Promise.resolve();

		if (self.rows[idx].sid)
			self.removed.push(self.rows[idx].sid);

		self.rows.splice(idx, 1);
		self.renderRows();

		return Promise.resolve();
	},

	readAll: function() {
		var self = this;

		self.rows.forEach(function(row) {
			if (row.elName)
				self.readRow(row);
		});
	},

	readRow: function(row) {
		row.name = trim(row.elName.value);
		row.target = trim(row.elTarget.value);
		row.public_port = trim(row.elPublic.value);
		row.dest_port = trim(row.elDestPort.value);
		row.proto = row.elProto.value || 'tcp';
		row.family = row.elFamily.value || 'any';
		row.enabled = !!row.elEnabled.checked;
	},

	validPortRange: function(v) {
		if (v == '')
			return true;

		return /^[0-9]+(-[0-9]+)?(\s+[0-9]+(-[0-9]+)?)*$/.test(v) &&
			v.split(/\s+/).every(function(p) {
				var a = p.split('-');
				var lo = parseInt(a[0], 10), hi = parseInt(a[a.length - 1], 10);

				return lo >= 1 && lo <= 65535 && hi >= lo && hi <= 65535;
			});
	},

	saveAll: function() {
		var self = this;
		var ops = [];
		var plan = [];
		var dropped = 0;

		self.removed.forEach(function(sid) {
			ops.push({ op: 'remove', sid: sid });
		});

		self.rows.forEach(function(row) {
			self.readRow(row);
		});

		/* Validate everything before staging anything, so a bad row cannot
		 * leave half-created sections in the uci session. */
		for (var i = 0; i < self.rows.length; i++) {
			var r = self.rows[i];
			var target = trim(r.target);
			var pub = trim(r.public_port);
			var dp = trim(r.dest_port);

			if (target == '路由器')
				target = '';

			/* The only row this page drops is a truly empty one. A row
			 * with a port and no target is an INPUT allow, not a
			 * half-filled forward. */
			if (pub == '' && dp == '' && target == '') {
				dropped++;
				if (r.sid)
					ops.push({ op: 'remove', sid: r.sid });
				continue;
			}

			var wantType = target ? 'redirect' : 'rule';
			var port = dp || pub;	/* effective WAN/service port */
			var fam = target ? ipFamily(target) : 0;

			/* IPv6 target without port translation: the packet is
			 * already addressed to the host, so DNAT would be a
			 * no-op. nf_nat then does not mark the conntrack as dnat
			 * and fw4's "ct status dnat accept" never matches; the
			 * packet falls through to the WAN reject. A plain
			 * forward accept is the correct rule here. */
			var fwd = (wantType == 'redirect' && fam == 6 &&
				(pub == '' || pub == dp));

			if (!self.validPortRange(pub) || !self.validPortRange(dp)) {
				return ui.addNotification(null, E('p', {}, [
					_('目标端口/公网端口格式不对：%s（支持 8080、8000-8010、空格分隔）').format(pub || dp)
				]), 'danger');
			}

			if (port == '') {
				return ui.addNotification(null, E('p', {}, [
					_('请至少填写目标端口或公网端口。')
				]), 'danger');
			}

			if (wantType == 'redirect') {
				if (!fam) {
					return ui.addNotification(null, E('p', {}, [
						_('“目标”必须是 IPv4/IPv6 地址，或留空/填“路由器”表示放行到路由器。')
					]), 'danger');
				}

				if (r.family == 'ipv4' && fam != 4) {
					return ui.addNotification(null, E('p', {}, [
						_('目标是 IPv6 地址 %s，但地址族选了 IPv4。').format(target)
					]), 'danger');
				}

				if (r.family == 'ipv6' && fam != 6) {
					return ui.addNotification(null, E('p', {}, [
						_('目标是 IPv4 地址 %s，但地址族选了 IPv6。').format(target)
					]), 'danger');
				}
			}

			plan.push({ row: r, target: target, pub: pub, dp: dp,
				port: port, type: wantType, fwd: fwd });
		}

		if (ops.length == 0 && plan.length == 0) {
			if (dropped)
				ui.addNotification(null, E('p', {}, [
					_('没有可保存的规则：%s 个空行已忽略。').format(dropped)
				]), 'warning');
			else
				ui.addNotification(null, E('p', {}, [
					_('没有规则可保存。')
				]), 'warning');

			return Promise.resolve();
		}

		function setOpt(sid, opt, val) {
			ops.push(val == ''
				? { op: 'unset', sid: sid, opt: opt }
				: { op: 'set', sid: sid, opt: opt, val: val });
		}

		plan.forEach(function(p) {
			var r = p.row;
			var sid = r.sid;

			/* UCI section types cannot be changed in place. If the row's
			 * kind changed (a target was added or removed), drop the old
			 * section and create the correct type. */
			if (sid && r.secType != p.type) {
				ops.push({ op: 'remove', sid: sid });
				sid = null;
			}

			if (!sid) {
				sid = uci.add('firewall', p.type);
				r.sid = sid;
				r.secType = p.type;
			}

			setOpt(sid, 'name', MARKER + (r.name || 'rule'));
			setOpt(sid, 'proto', r.proto);
			setOpt(sid, 'family', r.family || 'any');
			setOpt(sid, 'enabled', r.enabled ? '1' : '0');
			/* Older rows carry dpd_simple=1; it is not a fw4 option
			 * (fw4 logs an unknown-option warning and the section is
			 * not applied), so remove it on save. */
			if (uci.get('firewall', sid, 'dpd_simple') !== undefined)
				ops.push({ op: 'unset', sid: sid, opt: 'dpd_simple' });
			setOpt(sid, 'src', 'wan');

			if (p.type == 'rule') {
				/* src=wan + target=ACCEPT is an INPUT allow. No dest
				 * zone: a rule with dest=lan would match forwarded
				 * traffic instead. */
				setOpt(sid, 'dest', '');
				setOpt(sid, 'dest_port', p.dp || p.pub);
				setOpt(sid, 'src_dport', '');
				setOpt(sid, 'dest_ip', '');
				setOpt(sid, 'target', 'ACCEPT');
			}
			else if (p.fwd) {
				/* IPv6, same public and internal port: forward the
				 * packet to the host unchanged. */
				setOpt(sid, 'dest', 'lan');
				setOpt(sid, 'src_dport', '');
				setOpt(sid, 'dest_ip', p.target);
				setOpt(sid, 'dest_port', p.dp || p.pub);
				setOpt(sid, 'target', 'ACCEPT');
			}
			else {
				setOpt(sid, 'dest', 'lan');
				setOpt(sid, 'src_dport', p.pub || p.dp);
				setOpt(sid, 'dest_ip', p.target);
				setOpt(sid, 'dest_port', p.dp || p.pub);
				setOpt(sid, 'target', 'DNAT');
			}
		});

		/* Stage the ops through the LuCI uci RPC: it writes into the
		 * session's config delta, which uci apply then commits. */
		ops.forEach(function(o) {
			if (o.op == 'remove') {
				uci.remove('firewall', o.sid);
			}
			else if (o.op == 'unset') {
				if (uci.get('firewall', o.sid, o.opt) !== undefined)
					uci.unset('firewall', o.sid, o.opt);
			}
			else {
				uci.set('firewall', o.sid, o.opt, o.val);
			}
		});

		/* Commit + reload: uci apply runs the config-change triggers, so fw4
		 * reloads and the ACL guard re-imports the ports without a shell
		 * exec (rollback=false: no confirm timer, no 10 s stall). */
		return uci.save().then(function() {
			return callApply(0, false);
		}).then(function() {
			return self.reload();
		}).then(function() {
			if (dropped)
				ui.addNotification(null, E('p', {}, [
					_('已保存并应用；%s 个空行已忽略。').format(dropped)
				]), 'info');
			else
				ui.addNotification(null, E('p', {}, [ _('已保存并应用') ]), 'info');
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [
				e.message || String(e)
			]), 'danger');
		});
	},

	reload: function() {
		var self = this;

		uci.unload([ 'firewall' ]);

		return uci.load('firewall').then(function() {
			self.collect();
			self.renderRows();
			self.renderWarning();
		});
	}
});
