import { flushSync, mount, unmount } from 'svelte';
import { describe, expect, it } from 'vitest';
import Credentials from './Credentials.svelte';

const shown = (via: { label: string; conn: string }[]) => ({
	name: 'alice_app',
	username: 'alice_app',
	password: 'S3cretPasswordShownExactlyOnce00',
	conn: 'postgresql://alice_app:S3cretPasswordShownExactlyOnce00@edge:6432/alice_app',
	via
});

describe('Credentials', () => {
	// The screen that shows a password exactly once must render whatever the
	// server sends. Two listeners sharing a label is a legal, normal setup, and
	// a keyed each-block threw on it, leaving an error page where the only copy
	// of the credential should have been (CRYPTARCH-139).
	it('renders the credential when two listeners share a label', () => {
		const target = document.createElement('div');
		const app = mount(Credentials, {
			target,
			props: {
				heading: 'Database ready',
				shown: shown([
					{ label: 'lan', conn: 'postgresql://a@10.0.0.1:6432/alice_app' },
					{ label: 'lan', conn: 'postgresql://a@10.0.0.2:6432/alice_app' }
				])
			}
		});
		flushSync();
		const html = target.innerHTML;
		expect(html).toContain('S3cretPasswordShownExactlyOnce00');
		expect(html).toContain('10.0.0.1');
		expect(html).toContain('10.0.0.2');
		unmount(app);
	});
});
