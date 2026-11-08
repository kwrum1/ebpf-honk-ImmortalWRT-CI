'use strict';
'require view';
'require rpc';
'require ui';

var callPlugins = rpc.declare({ object: 'dpd', method: 'plugins', expect: { '': {} } });

return view.extend({
	load: function() { return callPlugins(); },
	render: function(data) {
		var honk = (data && data.honk) || {};
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, 'DPD / Honk'),
			E('div', { 'class': 'cbi-section' }, [
				E('p', {}, 'Honk 是 DPD 唯一的代理插件。代理数据面由 Honk 自己管理，DPD 只读取它的状态。'),
				E('p', {}, '运行状态：' + (honk.running ? '运行中' : '已停止')),
				E('p', {}, '版本：' + (honk.version || '未知')),
				E('div', { 'class': 'cbi-page-actions' }, [
					E('a', { 'class': 'cbi-button cbi-button-action', 'href': L.url('admin/network/proxy') }, '打开 Honk 页面')
				])
			])
		]);
	},
	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
