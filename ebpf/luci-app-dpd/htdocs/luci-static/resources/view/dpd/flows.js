'use strict';
'require view';
'require rpc';
'require ui';

var callStatus = rpc.declare({ object: 'dpd', method: 'status', expect: { '': {} } });

return view.extend({
	load: function() { return callStatus(); },
	render: function(data) {
		var dpd = (data && data.dpd) || {};
		var maps = dpd.maps || {};
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, 'DPD 流表（诊断）'),
			E('div', { 'class': 'cbi-section' }, [
				E('p', {}, '流表：' + (maps.flows ? maps.flows.entries + ' / ' + maps.flows.max_entries : '未知')),
				E('p', {}, 'IPv4：' + (maps.flows ? maps.flows.v4 : '?') + '，IPv6：' + (maps.flows ? maps.flows.v6 : '?')),
				E('pre', {}, JSON.stringify(maps, null, 2))
			])
		]);
	},
	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
