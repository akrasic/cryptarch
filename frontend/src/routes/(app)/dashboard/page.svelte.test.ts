import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('$app/paths', () => ({
	resolve: (id: string, params: Record<string, string> = {}) =>
		id.replace(/\/\([^)]+\)/g, '').replace(/\[(\w+)\]/g, (_: string, k: string) => params[k]) || '/'
}));
const { default: Page } = await import('./+page.svelte');
const { setNotice, takeNotice } = await import('#lib/notice.svelte.js');

type Quota = { used: number; limit: number | null; at_cap: boolean; known?: boolean };
const db = (name: string, status = 'active') => ({ name, status, server_name: 'local' });

let target: HTMLElement;
function render(databases: ReturnType<typeof db>[], quota: Quota, listed = true) {
	target = document.createElement('div');
	document.body.append(target);
	const list = { databases, listed, quota: { known: true, ...quota } };
	const app = mount(Page, { target, props: { data: { list } } as never });
	flushSync();
	return app;
}
afterEach(() => {
	target.remove();
	takeNotice();
});

const newButtons = () => [...target.querySelectorAll('a')].filter((a) => a.textContent === 'New database');

describe('the dashboard', () => {
	it('says the quota in the header and lists each database, linked to its first section', () => {
		const app = render([db('eddy'), db('orders', 'deleting')], { used: 2, limit: 5, at_cap: false });
		expect(target.querySelector('.page-head p')?.textContent).toContain('2 of 5 in use.');
		const rows = [...target.querySelectorAll('#databases tbody tr')];
		expect(rows.map((r) => r.querySelector('a.row-link')?.getAttribute('href'))).toEqual(['/db/eddy/connect', '/db/orders/connect']);
		expect(rows[1].querySelector('.badge')?.className).toBe('badge badge-danger');
		expect(newButtons().map((a) => a.getAttribute('href'))).toEqual(['/provision']);
		unmount(app);
	});

	it('says there is no limit rather than a number', () => {
		const app = render([db('eddy')], { used: 1, limit: null, at_cap: false });
		expect(target.querySelector('.page-head p')?.textContent).toContain('1 in use; your account has no limit.');
		unmount(app);
	});

	it('at the cap, says why there is no New database instead of offering one', () => {
		// Premise: below the cap the same list offers it (above).
		const app = render([db('a'), db('b')], { used: 2, limit: 2, at_cap: true });
		expect(target.querySelector('#at-cap')?.textContent).toContain('Quota reached.');
		expect(target.querySelector('#at-cap')?.textContent).toContain('2 of 2');
		expect(newButtons()).toEqual([]);
		unmount(app);
	});

	it('with nothing yet, offers the first one in the empty state', () => {
		const app = render([], { used: 0, limit: 3, at_cap: false });
		expect(target.querySelector('#no-databases h2')?.textContent).toBe('No databases yet');
		expect(target.querySelector('#databases')).toBeNull();
		expect(newButtons()).toHaveLength(1);
		expect(target.querySelector('#no-databases')!.contains(newButtons()[0])).toBe(true);
		unmount(app);
	});

	it('offers nothing to provision with a quota of none, and says to ask rather than to delete', () => {
		const app = render([], { used: 0, limit: 0, at_cap: true });
		expect(target.querySelector('#at-cap')?.textContent).toContain('No quota yet.');
		expect(target.querySelector('#at-cap')?.textContent).not.toContain('Delete one');
		expect(target.querySelector('#no-databases')?.textContent).toContain('does not allow one yet');
		expect(target.querySelector('#no-databases')?.textContent).not.toContain('Provision one');
		expect(newButtons()).toEqual([]);
		unmount(app);
	});

	it('says the list could not be loaded, rather than that there are none', () => {
		// Premise: the same empty list, read, is "No databases yet".
		const read = render([], { used: 0, limit: 3, at_cap: false });
		expect(target.querySelector('#no-databases')).not.toBeNull();
		unmount(read);
		target.remove();
		const app = render([], { used: 0, limit: 3, at_cap: false }, false);
		expect(target.querySelector('#list-unavailable h2')?.textContent).toBe('Your databases could not be loaded');
		expect(target.querySelector('#no-databases')).toBeNull();
		unmount(app);
	});

	it('says the quota could not be read, rather than that there is no limit', () => {
		const app = render([db('eddy')], { used: 1, limit: null, at_cap: false, known: false });
		const desc = target.querySelector('.page-head p')?.textContent ?? '';
		expect(desc).toContain('could not be read');
		expect(desc).not.toContain('no limit');
		unmount(app);
	});

	it('shows a notice left by a delete once, with its edge warning as an alert', () => {
		setNotice({ message: 'eddy deleted.', warning: 'Edge sync FAILED' });
		const app = render([], { used: 0, limit: 3, at_cap: false });
		expect(target.querySelector('[role=status]')?.textContent).toBe('eddy deleted.');
		expect(target.querySelector('[role=alert]')?.textContent).toBe('Edge sync FAILED');
		expect(takeNotice()).toBeNull();
		unmount(app);
	});
});
