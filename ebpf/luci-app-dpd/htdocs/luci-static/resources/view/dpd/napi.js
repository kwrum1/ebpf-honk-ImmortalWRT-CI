'use strict';
'require view';
'require rpc';
'require ui';

var callPlugins = rpc.declare({ object: 'dpd', method: 'plugins', expect: { '': {} } });

return view.extend({
	load: function() { return callPlugins(); },
	render: function(data) {
		var napi = (data && data.napi) || {};
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, 'DPD / NAPI'),
			E('div', { 'class': 'cbi-section' }, [
				E('p', {}, '启用：' + (napi.enabled ? '是' : '否')),
				E('p', {}, 'netdev_budget：' + (napi.netdev_budget || '?') +
					'，dev_weight：' + (napi.dev_weight || '?')),
				E('p', {}, 'gro_flush_timeout：' + (napi.gro_flush_timeout || 0) +
					'，napi_defer_hard_irqs：' + (napi.napi_defer_hard_irqs || 0)),
				E('pre', {}, JSON.stringify(napi, null, 2))
			])
		]);
	},
	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
