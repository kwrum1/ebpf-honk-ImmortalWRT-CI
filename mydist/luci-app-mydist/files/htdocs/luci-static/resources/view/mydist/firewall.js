'use strict';
'require view';
'require form';
'require uci';
'require fs';

/* Network -> 防火墙: five-tuple port control, one rule per row.
 *
 * Posture: firewall.mydist999 (src wan -> dest lan, reject, v4+v6) is always
 * enabled by mydist-posture and is not editable here. Every row below is a
 * stock fw4 redirect: IPv4 gets DNAT, IPv6 gets the matching accept.
 *
 * Rows are edited inline. src=wan, dest=lan and target=DNAT are filled in on
 * save, so the table only asks for the five tuple. A row that is still
 * incomplete (no source port or no destination address) is dropped instead of
 * being handed to fw4.
 */

return view.extend({
	load: function() {
		return uci.load('firewall');
	},

	render: function() {
		var m, s, o;

		m = new form.Map('firewall', _('防火墙'));

		s = m.section(form.GridSection, 'redirect', _('端口控制'));
		s.anonymous = true;
		s.addremove = true;
		s.sortable = false;
		s.nodescriptions = true;

		o = s.option(form.Value, 'name', _('名称'));
		o.modalonly = false;
		o.placeholder = _('可选');
		o.rmempty = true;

		o = s.option(form.ListValue, 'proto', _('协议'));
		o.modalonly = false;
		o.value('tcp', 'TCP');
		o.value('udp', 'UDP');
		o.value('tcp udp', 'TCP+UDP');
		o.default = 'tcp';
		o.rmempty = true;
		o.cfgvalue = function(section_id) {
			var v = uci.get('firewall', section_id, 'proto');
			return (v == null) ? 'tcp' : (Array.isArray(v) ? v.join(' ') : v);
		};

		o = s.option(form.Value, 'src_dport', _('源端口'));
		o.modalonly = false;
		o.placeholder = '8080 / 8000-8010';
		o.datatype = 'portrange';
		o.rmempty = true;

		o = s.option(form.Value, 'src_ip', _('源地址'));
		o.modalonly = false;
		o.placeholder = _('任意');
		o.datatype = 'ipmask';
		o.rmempty = true;

		o = s.option(form.Value, 'dest_ip', _('目的地址'));
		o.modalonly = false;
		o.placeholder = '192.168.1.10';
		o.datatype = 'ipmask';
		o.rmempty = true;

		o = s.option(form.Value, 'dest_port', _('目的端口'));
		o.modalonly = false;
		o.placeholder = _('同源端口');
		o.datatype = 'portrange';
		o.rmempty = true;

		o = s.option(form.Flag, 'enabled', _('启用'));
		o.modalonly = false;
		o.default = o.enabled;
		o.rmempty = false;

		var save = m.save.bind(m);

		m.save = function(cb, silent) {
			return save(cb, silent).then(function() {
				/* the grid's Add/Remove buttons save silently; a row that was
				 * just added is still empty and must survive until the user
				 * fills it and presses Save. */
				if (silent)
					return;

				var changed = false;

				uci.sections('firewall', 'redirect', function(sec) {
					var id = sec['.name'];
					var sd = uci.get('firewall', id, 'src_dport') || '';
					var dip = uci.get('firewall', id, 'dest_ip') || '';

					if (!sd || !dip) {
						uci.remove('firewall', id);
						changed = true;
						return;
					}

					if (!uci.get('firewall', id, 'src')) {
						uci.set('firewall', id, 'src', 'wan');
						changed = true;
					}
					if (!uci.get('firewall', id, 'dest')) {
						uci.set('firewall', id, 'dest', 'lan');
						changed = true;
					}
					if (!uci.get('firewall', id, 'target')) {
						uci.set('firewall', id, 'target', 'DNAT');
						changed = true;
					}
					if (!uci.get('firewall', id, 'dest_port')) {
						uci.set('firewall', id, 'dest_port', sd);
						changed = true;
					}
					if (!uci.get('firewall', id, 'proto')) {
						uci.set('firewall', id, 'proto', 'tcp');
						changed = true;
					}
				});

				var commit = changed ? uci.save() : Promise.resolve();

				return commit.then(function() {
					return fs.exec('/etc/init.d/firewall', [ 'reload' ]).catch(function() {});
				});
			});
		};

		return m.render();
	}
});
