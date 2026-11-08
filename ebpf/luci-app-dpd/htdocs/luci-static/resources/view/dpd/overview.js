'use strict';
'require view';
'require rpc';
'require ui';

var callStatus = rpc.declare({
	object: 'dpd',
	method: 'status',
	expect: { '': {} }
});
var callPlugins = rpc.declare({
	object: 'dpd',
	method: 'plugins',
	expect: { '': {} }
});

function row(label, value) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title' }, label),
		E('div', { 'class': 'cbi-value-field' }, value)
	]);
}

function bool(v) { return v === true || v === 1 || v === '1' ? '是' : '否'; }

return view.extend({
	load: function() {
		return Promise.all([ callStatus(), callPlugins() ]);
	},

	render: function(data) {
		var status = data[0] || {};
		var plugins = data[1] || {};
		var dpd = status.dpd || {};
		var gate = status.gate || {};
		var honk = plugins.honk || status.honk || {};
		var napi = plugins.napi || status.napi || {};
		var cfg = dpd.cfg || {};
		var maps = dpd.maps || {};

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, 'DPD 插件'),
			E('div', { 'class': 'cbi-section' }, [
				E('p', { 'class': 'cbi-section-descr' },
					'数据面状态仍显示在 Vantage 首页的加速卡片里；这里只管理代理、NAPI 等插件。'),
				row('数据面', (cfg.mode || '未知') + (dpd.attached ? ' / 已挂载 ABI ' + (dpd.abi || '?') : ' / 未挂载')),
				row('Gate', (gate.effective || '未知') + (gate.reason ? ' — ' + gate.reason : '')),
				row('流表', maps.flows ? maps.flows.entries + ' / ' + maps.flows.max_entries : '未知'),
				row('Honk 代理', (bool(honk.running) === '是' ? '运行中' : '已停止') +
					(honk.version ? ' · ' + honk.version : '')),
				row('NAPI 调优', bool(napi.enabled) === '是' ? '已启用' : '未启用'),
				E('div', { 'class': 'cbi-page-actions' }, [
					E('a', { 'class': 'cbi-button cbi-button-action', 'href': L.url('admin/network/proxy') }, '打开 Honk'),
					' ',
					E('a', { 'class': 'cbi-button', 'href': L.url('admin/network/firewall') }, '防火墙'),
					' ',
					E('a', { 'class': 'cbi-button', 'href': L.url('admin/network/mwan') }, '多 WAN')
				])
			])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
