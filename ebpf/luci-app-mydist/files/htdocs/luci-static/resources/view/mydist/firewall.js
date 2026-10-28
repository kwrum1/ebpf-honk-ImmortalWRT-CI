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

/* Network -> 防火墙: five-tuple port control, one WAN redirect per row.
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
 * Rows are written through the uci RPC (the ACL-covered path, not /sbin/uci).
 * src=wan, dest=lan and target=DNAT
 * are filled in on save so the table only asks for the five tuple. An
 * incomplete row (no source port or no destination address) is dropped instead
 * of being handed to fw4.
 */

function uciVal(v) {
	if (v == null)
		return '';

	return Array.isArray(v) ? v.join(' ') : String(v);
}

function uciProto(v) {
	v = uciVal(v).trim();

	if (v == '')
		return 'tcp';

	return v.split(/\s+/).sort().join(' ');
}

return view.extend({
	/* The LuCI view base class appends its own Save & Apply footer for every
	 * view that inherits handleSaveApply(). That footer calls
	 * ui.changes.apply() (the ubus/ACL path); this page has its own explicit
	 * button that stages through the uci RPC, so the extra button was both a
	 * duplicate and the source of the "no permission" error. Shadow the three
	 * handlers with null so the base
	 * footer is not rendered; the explicit button below the table is the only
	 * one. */
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		var self = this;

		self.rows = [];
		self.removed = [];

		return uci.load('firewall').then(function() {
			self.collect();
		});
	},

	collect: function() {
		var self = this;

		self.rows = [];
		self.removed = [];

		uci.sections('firewall', 'redirect', function(sec) {
			var src = uciVal(sec.src);
			var dest = uciVal(sec.dest);
			var target = uciVal(sec.target);

			/* This page owns WAN DNAT port forwards. Do not touch a redirect
			 * that another page/user pointed at a different zone or target. */
			if ((src != '' && src != 'wan') ||
			    (dest != '' && dest != 'lan') ||
			    (target != '' && target != 'DNAT'))
				return;

			self.rows.push({
				sid: sec['.name'],
				name: uciVal(sec.name),
				proto: uciProto(sec.proto),
				src_dport: uciVal(sec.src_dport),
				src_ip: uciVal(sec.src_ip),
				dest_ip: uciVal(sec.dest_ip),
				dest_port: uciVal(sec.dest_port),
				enabled: uciVal(sec.enabled) != '0'
			});
		});
	},

	render: function() {
		var self = this;

		self.tbody = E('tbody');

		self.renderRows();

		var table = E('table', { 'class': 'table' }, [
			E('thead', {}, [
				E('tr', { 'class': 'tr table-titles' }, [
					E('th', { 'class': 'th' }, [ _('名称') ]),
					E('th', { 'class': 'th' }, [ _('协议') ]),
					E('th', { 'class': 'th' }, [ _('源端口') ]),
					E('th', { 'class': 'th' }, [ _('源地址') ]),
					E('th', { 'class': 'th' }, [ _('目的地址') ]),
					E('th', { 'class': 'th' }, [ _('目的端口') ]),
					E('th', { 'class': 'th' }, [ _('启用') ]),
					E('th', { 'class': 'th' }, [ _('操作') ])
				])
			]),
			self.tbody
		]);

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [ _('防火墙') ]),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('WAN 入站端口控制：每一行是一条 fw4 redirect。' +
				  '只填源端口和目的地址即可；目的端口留空时与源端口相同，' +
				  'src=wan / dest=lan / target=DNAT 会自动补齐。')
			]),

			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [ _('端口控制') ]),
				table,
				E('div', { 'class': 'cbi-section-create' }, [
					E('button', {
						'class': 'cbi-button cbi-button-add',
						click: function() { return self.addRow(); }
					}, [ _('添加规则') ])
				]),
				E('div', { 'class': 'cbi-value-description' }, [
					_('“添加规则”直接加一行，不弹确认框；填好后点下面的“保存并应用”。')
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

		row.elName = input(row.name, _('可选'), '9em');
		row.elSrcDport = input(row.src_dport, '8080 / 8000-8010', '10em');
		row.elSrcIp = input(row.src_ip, _('任意'), '9em');
		row.elDestIp = input(row.dest_ip, '192.168.1.10', '10em');
		row.elDestPort = input(row.dest_port, _('同源端口'), '8em');

		var protos = [ 'tcp', 'udp', 'tcp udp' ];

		if (protos.indexOf(row.proto) < 0)
			protos.push(row.proto);

		row.elProto = E('select', { 'class': 'cbi-input-select' },
			protos.map(function(p) {
				var label = (p == 'tcp') ? 'TCP' :
					(p == 'udp') ? 'UDP' :
					(p == 'tcp udp') ? 'TCP+UDP' : p;

				return E('option', { 'value': p }, [ label ]);
			}));
		row.elProto.value = row.proto;

		row.elEnabled = E('input', { 'type': 'checkbox' });
		row.elEnabled.checked = row.enabled;

		return E('tr', { 'class': 'tr' }, [
			E('td', { 'class': 'td' }, [ row.elName ]),
			E('td', { 'class': 'td' }, [ row.elProto ]),
			E('td', { 'class': 'td' }, [ row.elSrcDport ]),
			E('td', { 'class': 'td' }, [ row.elSrcIp ]),
			E('td', { 'class': 'td' }, [ row.elDestIp ]),
			E('td', { 'class': 'td' }, [ row.elDestPort ]),
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
			name: '',
			proto: 'tcp',
			src_dport: '',
			src_ip: '',
			dest_ip: '',
			dest_port: '',
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
		row.name = String(row.elName.value || '').trim();
		row.proto = row.elProto.value || 'tcp';
		row.src_dport = String(row.elSrcDport.value || '').trim();
		row.src_ip = String(row.elSrcIp.value || '').trim();
		row.dest_ip = String(row.elDestIp.value || '').trim();
		row.dest_port = String(row.elDestPort.value || '').trim();
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

	validIPMask: function(v) {
		if (v == '')
			return true;

		return /^[0-9a-fA-F:.]+\/[0-9]{1,3}$/.test(v) ||
			/^[0-9a-fA-F:.]+$/.test(v);
	},

	saveAll: function() {
		var self = this;
		var ops = [];

		self.removed.forEach(function(sid) {
			ops.push({ op: 'remove', sid: sid });
		});

		self.rows.forEach(function(row) {
			self.readRow(row);
		});

		for (var i = 0; i < self.rows.length; i++) {
			var r = self.rows[i];

			if (!self.validPortRange(r.src_dport) || !self.validPortRange(r.dest_port))
				return ui.addNotification(null, E('p', {}, [
					_('源端口/目的端口格式不对：%s').format(r.src_dport || r.dest_port)
				]), 'danger');

			if (!self.validIPMask(r.src_ip) || !self.validIPMask(r.dest_ip))
				return ui.addNotification(null, E('p', {}, [
					_('源/目的地址格式不对：%s').format(r.src_ip || r.dest_ip)
				]), 'danger');

			/* Incomplete rows carry no usable rule. Drop new ones; remove an
			 * existing one so fw4 does not keep a half-written redirect. */
			if (!r.src_dport || !r.dest_ip) {
				if (r.sid)
					ops.push({ op: 'remove', sid: r.sid });
				continue;
			}

			var sid = r.sid;

			if (!sid) {
				sid = uci.add('firewall', 'redirect');
				r.sid = sid;
			}

			var set = function(opt, val) {
				ops.push(val == ''
					? { op: 'unset', sid: sid, opt: opt }
					: { op: 'set', sid: sid, opt: opt, val: val });
			};

			set('name', r.name);
			set('proto', r.proto);
			set('src_dport', r.src_dport);
			set('src_ip', r.src_ip);
			set('dest_ip', r.dest_ip);
			set('dest_port', r.dest_port || r.src_dport);
			set('enabled', r.enabled ? '1' : '0');

			/* Non-tuple parts are this page's contract with fw4. */
			set('src', 'wan');
			set('dest', 'lan');
			set('target', 'DNAT');
		}

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
			ui.addNotification(null, E('p', {}, [ _('已保存并应用') ]), 'info');
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [ e.message || String(e) ]), 'danger');
		});
	},
	reload: function() {
		var self = this;

		uci.unload([ 'firewall' ]);

		return uci.load('firewall').then(function() {
			self.collect();
			self.renderRows();
		});
	}
});
