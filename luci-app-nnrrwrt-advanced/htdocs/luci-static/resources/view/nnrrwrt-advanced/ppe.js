// SPDX-License-Identifier: Apache-2.0

'use strict';
'require form';
'require view';

return view.extend({
	render: function() {
		var m, s, o;

		m = new form.Map('airoha_accel', _('PPE Binding'),
			_('PPE sends a flow to hardware after its packet rate reaches the configured threshold. Lower values offload flows sooner; higher values keep short flows on the CPU.'));

		s = m.section(form.NamedSection, 'ppe', 'airoha_accel', _('Binding thresholds'));
		s.anonymous = true;
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('Use custom thresholds'));
		o.default = '0';
		o.rmempty = false;
		o.description = _('When disabled, the kernel uses the upstream 30 packets per second threshold for L2 and L3 flows.');

		o = s.option(form.Value, 'bind_rate_l2b', _('L2 bridge threshold (pps)'),
			_('Packet rate that moves a bridged flow from software processing to PPE.'));
		o.default = '10';
		o.placeholder = '10';
		o.datatype = 'range(1,65535)';
		o.rmempty = false;
		o.depends('enabled', '1');

		o = s.option(form.Value, 'bind_rate_l3', _('L3 routing threshold (pps)'),
			_('Packet rate that moves a routed or NAT flow from software processing to PPE.'));
		o.default = '10';
		o.placeholder = '10';
		o.datatype = 'range(1,65535)';
		o.rmempty = false;
		o.depends('enabled', '1');

		return m.render();
	}
});
