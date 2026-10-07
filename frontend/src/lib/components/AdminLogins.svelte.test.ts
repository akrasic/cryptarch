import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import AdminLogins, { type Logins, type ServerLogins } from './AdminLogins.svelte';

const server = (verdict: ServerLogins['verdict'], over: Partial<ServerLogins> = {}): ServerLogins => ({
	server_name: verdict, verdict, detail: null, roles_checked: 2, roles_failed: null, known_databases: 1,
	disabled: [], unknown_to_metadata: [], ...over
});
const report = (over: Partial<Logins> = {}): Logins => ({
	summary: { findings: 0, checked: 1, unchecked: 0 }, servers: [], stranded: [], unreachable_at_upgrade: [], ...over
});
function open(r: Logins) {
	const target = document.createElement('div');
	document.body.append(target);
	const onchanged = vi.fn(async () => {});
	const app = mount(AdminLogins, { target, props: { report: r, onchanged } });
	flushSync();
	return { app, target, onchanged };
}
afterEach(() => {
	vi.unstubAllGlobals();
	document.body.innerHTML = '';
});

describe('AdminLogins', () => {
	it('words every verdict differently, and never "clean" for one that could not look', () => {
		const verdicts: ServerLogins['verdict'][] = ['not_checked', 'partial', 'not_surveyed', 'inconclusive', 'sources_disagree', 'clean', 'findings'];
		const texts = verdicts.map((v) => {
			const { app, target } = open(report({ servers: [server(v, { detail: 'why' })] }));
			const t = target.querySelector('.server-report')!.textContent!.replace(v, '').replace(/\s+/g, ' ');
			unmount(app);
			return t;
		});
		expect(new Set(texts).size).toBe(verdicts.length);
		for (const i of [0, 3]) expect(texts[i]).toContain('not a clean result');
		expect(texts[2]).toContain('Nothing here was ruled out');
		expect(texts[1]).toContain('absence proves nothing');
		expect(texts[4]).toContain('Sources disagree');
		expect(texts[5]).toContain('No findings');
	});

	it('always states both numbers', () => {
		const a = open(report({ summary: { findings: 0, checked: 2, unchecked: 1 } }));
		expect(a.target.querySelector('.summary')!.textContent).toContain('1 server(s) could not be checked');
		unmount(a.app);
		const b = open(report({ summary: { findings: 0, checked: 2, unchecked: 0 } }));
		expect(b.target.querySelector('.summary')!.textContent).toContain('0 servers could not be checked.');
		unmount(b.app);
	});

	it('lists findings with their cause, and roles metadata does not name', () => {
		const { app, target } = open(report({ servers: [server('findings', {
			disabled: [{ role_name: 'alice_db', db_name: 'alice_db', cause: 'failed_delete' }, { role_name: 'ghost', db_name: null, cause: 'unknown' }],
			unknown_to_metadata: ['stray']
		})] }));
		const rows = [...target.querySelectorAll('tbody tr')].map((r) => r.textContent);
		expect(rows[0]).toContain('A delete began and did not finish.');
		expect(rows[1]).toContain('not in metadata');
		expect(target.textContent).toContain('stray');
		unmount(app);
	});

	it('offers nothing it could not check, nor a name someone else is provisioning', () => {
		const { app, target } = open(report({ stranded: [
			{ name: 'dark_db', can_log_in: null, db_exists: null, retryable: false },
			{ name: 'inflight_db', can_log_in: true, db_exists: false, retryable: false }
		] }));
		expect([...target.querySelectorAll('button')].some((b) => b.textContent === 'Finish delete')).toBe(false);
		const text = target.textContent!.replace(/\s+/g, ' ');
		expect(text).toContain('could not be asked');
		expect(text).toContain('Not ours to finish');
		expect(text).not.toContain('no data left to lose');
		unmount(app);
	});

	it('shows findings as something to look at, and only a clean check as green', () => {
		const clean = open(report({ servers: [server('clean')] }));
		expect(clean.target.querySelector('.server-report .badge-ok')?.textContent).toBe('Checked');
		unmount(clean.app);
		document.body.innerHTML = '';
		const found = open(report({ servers: [server('findings')] }));
		expect(found.target.querySelector('.server-report .badge-warn')?.textContent).toBe('Findings');
		expect(found.target.querySelector('.server-report .badge-ok')).toBeNull();
		unmount(found.app);
	});

	it('never shows a verdict it does not know as checked', () => {
		const { app, target } = open(report({ servers: [server('mystery' as ServerLogins['verdict'])] }));
		expect(target.querySelector('.server-report')!.textContent).toContain('Unknown');
		expect(target.querySelector('.badge-ok')).toBeNull();
		unmount(app);
	});

	it('offers to finish only a delete that began, and only with the name typed', async () => {
		const calls: { url: string; body: unknown }[] = [];
		vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
			calls.push({ url, body: JSON.parse(init!.body as string) });
			return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'Content-Type': 'application/json' } });
		}));
		const { app, target, onchanged } = open(report({ stranded: [
			{ name: 'intact_db', can_log_in: true, db_exists: true, retryable: false },
			{ name: 'half_db', can_log_in: false, db_exists: true, retryable: true }
		] }));
		const buttons = [...target.querySelectorAll('button')].filter((b) => b.textContent === 'Finish delete');
		expect(buttons).toHaveLength(1);
		expect(target.textContent).toContain('intact');
		buttons[0].click();
		flushSync();
		const field = target.querySelector<HTMLInputElement>('.dialog input[name=confirm]')!;
		field.value = ' half_db ';
		field.dispatchEvent(new Event('input'));
		flushSync();
		target.querySelector('.dialog form')!.dispatchEvent(new Event('submit', { cancelable: true }));
		await new Promise((r) => setTimeout(r, 0));
		flushSync();
		// Sent as typed: the server's check sees what the user typed.
		expect(calls).toEqual([{ url: '/api/v1/admin/logins/half_db/retry-delete', body: { confirm: ' half_db ' } }]);
		expect(target.querySelector('[role=status]')?.textContent).toBe('Delete completed.');
		await new Promise((r) => setTimeout(r, 0));
		expect(document.activeElement).toBe(target.querySelector('[role=status]'));
		expect(onchanged).toHaveBeenCalledOnce();
		unmount(app);
	});

	it('lands on a refused finish, and names each button by what it finishes', async () => {
		vi.stubGlobal('fetch', vi.fn(async () =>
			new Response(JSON.stringify({ error: { code: 'not_retryable', message: 'This delete can no longer be finished.' } }), { status: 409, headers: { 'Content-Type': 'application/json' } })
		));
		const { app, target } = open(report({ stranded: [{ name: 'half_db', can_log_in: false, db_exists: true, retryable: true }] }));
		const button = target.querySelector<HTMLButtonElement>('button[aria-label="Finish deleting half_db"]')!;
		button.click();
		flushSync();
		const field = target.querySelector<HTMLInputElement>('.dialog input[name=confirm]')!;
		field.value = 'half_db';
		field.dispatchEvent(new Event('input'));
		flushSync();
		target.querySelector('.dialog form')!.dispatchEvent(new Event('submit', { cancelable: true }));
		await new Promise((r) => setTimeout(r, 0));
		await new Promise((r) => setTimeout(r, 0));
		flushSync();
		const alert = target.querySelector('[role=alert]');
		expect(alert?.textContent).toBe('This delete can no longer be finished.');
		expect(document.activeElement).toBe(alert);
		unmount(app);
	});
});
