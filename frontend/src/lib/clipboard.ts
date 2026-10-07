// Copy-to-clipboard for credentials and connection strings, ported from
// navigator.clipboard only exists in secure contexts, and a plain-HTTP
// LAN deploy (the homelab norm) has none, so this falls back to the legacy
// execCommand path. If that fails too, the caller says so: these are
// show-once passwords, and silence is not ok.
export function copyText(text: string): Promise<void> {
	if (navigator.clipboard && window.isSecureContext) {
		return navigator.clipboard.writeText(text);
	}
	return new Promise((resolve, reject) => {
		const ta = document.createElement('textarea');
		ta.value = text;
		ta.setAttribute('readonly', '');
		// Set through the CSSOM, which the CSP (style-src 'self') permits —
		// unlike a style attribute in markup.
		ta.style.position = 'fixed';
		ta.style.left = '-9999px';
		document.body.appendChild(ta);
		ta.select();
		let ok = false;
		try {
			ok = document.execCommand('copy');
		} catch {
			/* fall through */
		}
		ta.remove();
		if (ok) resolve();
		else reject(new Error('execCommand copy failed'));
	});
}
