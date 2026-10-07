import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, it } from 'vitest';
import ContentsPanel, { type Contents } from './ContentsPanel.svelte';

function show(contents: Contents | null) {
	const target = document.createElement('div');
	document.body.append(target);
	const app = mount(ContentsPanel, { target, props: { contents } });
	flushSync();
	return { app, text: target.textContent!.replace(/\s+/g, ' '), target };
}
afterEach(() => (document.body.innerHTML = ''));

describe('ContentsPanel', () => {
	it('shows size, activity and tables, and a never-analyzed table as a dash, not -1', () => {
		const { app, text, target } = show({
			available: true, size_bytes: 19 * 1024 * 1024, active: true,
			tables: [
				{ name: 'shop_orders', approx_rows: 15000, total_bytes: 7.2 * 1024 * 1024 },
				{ name: 'never_analyzed', approx_rows: -1, total_bytes: 8192 }
			]
		});
		expect(text).toContain('19.0 MB');
		expect(text).toContain('In use now');
		expect(text).toContain('2 tables.');
		const rows = [...target.querySelectorAll('tbody tr')].map((r) => [...r.querySelectorAll('td')].map((c) => c.textContent));
		expect(rows[0]).toEqual(['shop_orders', '15000', '7.2 MB']);
		expect(rows[1]).toEqual(['never_analyzed', '—', '8.0 kB']);
		expect(text).not.toContain('-1');
		unmount(app);
	});

	it('keeps unavailable, unreadable and empty apart', () => {
		const texts = [
			show(null).text,
			show({ available: false }).text,
			show({ available: true, size_bytes: 0, active: false, tables: null }).text,
			show({ available: true, size_bytes: 0, active: false, tables: [] }).text
		];
		expect(texts[0]).toContain('Contents unavailable');
		expect(texts[1]).toContain('Contents unavailable');
		expect(texts[2]).toContain("isn't readable");
		expect(texts[2]).not.toContain('No tables yet');
		expect(texts[3]).toContain('No tables yet');
		expect(texts[3]).toContain('Idle');
	});
});
