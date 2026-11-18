// SPDX-License-Identifier: Apache-2.0

'use strict';
'require form';
'require fs';
'require view';

return view.extend({
	load: function() {
		return L.resolveDefault(fs.read_direct('/sys/module/airoha_xpon/parameters/dying_gasp'), '');
	},

	render: function(running) {
		var m, s, o;

		m = new form.Map('nnrrwrt_advanced', _('Advanced'),
			_('Settings of NNRRWrt features that the other configuration pages do not cover. Each tab states when a change takes effect.'));

		s = m.section(form.NamedSection, 'main', 'nnrrwrt_advanced');
		s.anonymous = true;
		s.addremove = false;

		s.tab('thermal', _('Thermal'));
		s.tab('dying_gasp', _('Dying gasp'));
		s.tab('crashlog', _('Crash log'));

		o = s.taboption('thermal', form.Value, 'throttle_temp', _('Throttling temperature (°C)'),
			_('The CPU frequency limit tightens one step per second while the temperature at or above this value keeps rising, relaxes while it falls, and is released once the temperature is 1 °C below it. The value applies to both CPU thermal zones at once and at every boot. Allowed range 60 to 110; the 120 °C shutdown temperature is fixed.'));
		o.datatype = 'range(60,110)';
		o.default = '95';
		o.placeholder = '95';
		o.rmempty = false;

		o = s.taboption('dying_gasp', form.Flag, 'dying_gasp', _('Act on supply drop'),
			_('On a supply drop the ONU signals a dying gasp on the PON, switches off USB power, holds the LAN 1 PHY in reset and reboots after 28 s if it keeps running. Takes effect after the next reboot. Only boards with the supply-drop interrupt wired use it (Nokia XG-040G-MD).'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('dying_gasp', form.DummyValue, '_running', _('State in the running system'));
		o.cfgvalue = function() {
			var value = String(running || '').trim();

			if (value == 'Y')
				return _('Enabled');
			if (value == 'N')
				return _('Disabled');
			return _('Unknown');
		};

		o = s.taboption('crashlog', form.Value, 'crashlog_keep', _('Crash records kept'),
			_('Number of records kept under /etc/crashlog after a panic, a dying gasp or an unclean reset. 0 saves no new records and keeps the existing ones. Takes effect at the next boot. Allowed range 0 to 10.'));
		o.datatype = 'range(0,10)';
		o.default = '5';
		o.placeholder = '5';
		o.rmempty = false;

		return m.render();
	}
});
