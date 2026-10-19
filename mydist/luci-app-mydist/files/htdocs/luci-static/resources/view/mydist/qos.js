'use strict';
'require view';
'require form';
'require uci';
'require fs';

/* Network -> QoS: CAKE on the uplink.
 *
 * CAKE shapes to the rate you give it, so nothing is installed while upload is
 * 0. Only the upload direction is shaped here: feeding an IFB for the download
 * direction either does not delay the real packet or steals it from
 * router-acl/dpd, so this page stays with the shaper that actually works.
 */

return view.extend({
	load: function() {
		return uci.load('router_qos');
	},

	render: function() {
		var m, s, o;

		m = new form.Map('router_qos', _('QoS'),
			_('在 WAN 出口整形（CAKE），上传速率按实际带宽填写。'));

		s = m.section(form.NamedSection, 'global', 'router_qos', _('接口整形'));
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('启用'));
		o.default = o.enabled;
		o.rmempty = false;

		o = s.option(form.Value, 'wan', _('整形接口'),
			_('netifd 逻辑名（wan / pppoe-wan）或设备名（eth1）'));
		o.default = 'wan';
		o.rmempty = false;
		o.placeholder = 'wan';

		o = s.option(form.Value, 'upload', _('上传速率'),
			_('单位 kbit/s，例如 100000 = 100 Mbit；0 表示不整形'));
		o.datatype = 'uinteger';
		o.default = '0';
		o.rmempty = false;
		o.placeholder = '100000';

		o = s.option(form.ListValue, 'diffserv', _('调度模式'));
		o.value('diffserv4', _('diffserv4（语音/视频优先）'));
		o.value('diffserv3', _('diffserv3（三档）'));
		o.value('besteffort', _('besteffort（只做公平）'));
		o.default = 'diffserv4';
		o.rmempty = false;

		o = s.option(form.Value, 'overhead', _('链路开销'),
			_('字节；PPPoE 常用 34（带 VLAN）或 8，以太网 0'));
		o.datatype = 'uinteger';
		o.default = '0';
		o.rmempty = true;
		o.placeholder = '0';

		o = s.option(form.Value, 'mpu', _('最小包大小'),
			_('字节，通常 0（不调整）或 64'));
		o.datatype = 'uinteger';
		o.default = '0';
		o.rmempty = true;
		o.placeholder = '0';

		o = s.option(form.Flag, 'wash', _('清除 DSCP'),
			_('不信任局域网主机设置的 DSCP'));
		o.default = '0';
		o.rmempty = false;

		o = s.option(form.Flag, 'nat', _('NAT 模式'),
			_('告诉 CAKE 路由器在做 NAT'));
		o.default = '0';
		o.rmempty = false;

		var save = m.save.bind(m);

		m.save = function(cb, silent) {
			return save(cb, silent).then(function() {
				if (silent)
					return;

				return fs.exec('/etc/init.d/router-qos', [ 'restart' ]).catch(function() {});
			});
		};

		return m.render();
	}
});
