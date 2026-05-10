'use strict';
'require view';

return view.extend({
	render: function() {
		var url = window.location.protocol + '//' + window.location.hostname + ':8095/';

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [ _('SiteWatch') ]),
			E('div', { 'class': 'cbi-section' }, [
				E('p', {}, [
					_('SiteWatch runs on a separate OpenWrt uhttpd listener and opens on port 8095.')
				]),
				E('p', {}, [
					E('a', {
						'class': 'btn cbi-button cbi-button-apply',
						'href': url,
						'target': '_blank',
						'rel': 'noreferrer noopener'
					}, [ _('Open SiteWatch') ])
				]),
				E('p', { 'class': 'cbi-value-description' }, [
					_('Direct URL: '), E('code', {}, [ url ])
				])
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
