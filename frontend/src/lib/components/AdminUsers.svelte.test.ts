import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import AdminNewUser from './AdminNewUser.svelte';
import AdminUserDetail from './AdminUserDetail.svelte';

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
function server(routes: Record<string, (Response | Promise<Response>)[]>) {
	const calls: { key: string; body: unknown }[] = [];
	vi.stubGlobal(
		'fetch',
		vi.fn(async (url: string, init?: RequestInit) => {
			const key = `${init?.method ?? 'GET'} ${url}`;
			calls.push({ key, body: init?.body ? JSON.parse(init.body as string) : undefined });
			const next = routes[key]?.shift();
			if (!next) throw new Error(`unexpected ${key}`);
			return next;
		})
	);
	return calls;
}
const settle = () => new Promise((r) => setTimeout(r, 0)).then(() => flushSync());
const button = (t: HTMLElement, text: string) =>
	[...t.querySelectorAll('button')].find((b) => b.textContent?.trim() === text);
// The confirm dialog's armed button.
const armed = (t: HTMLElement) => t.querySelector<HTMLButtonElement>('.dialog button.btn-danger-solid')!;
const set = (el: HTMLInputElement | HTMLSelectElement, v: string) => {
	el.value = v;
	el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input'));
};
afterEach(() => {
	vi.unstubAllGlobals();
	document.body.innerHTML = '';
});

const SECRET = 'GeneratedPasswordShownOnce000000';

describe('AdminNewUser', () => {
	function open() {
		const target = document.createElement('div');
		document.body.append(target);
		const app = mount(AdminNewUser, { target, props: { usersHref: '/admin/users' } });
		flushSync();
		return { app, target };
	}

	it('creates with what was chosen and shows the password once', async () => {
		const calls = server({ 'POST /api/v1/admin/users': [json(201, { username: 'carl', password: SECRET, is_admin: false })] });
		const { app, target } = open();
		set(target.querySelector('input[name=username]')!, 'carl');
		set(target.querySelector('select[name=quota]')!, 'unlimited');
		flushSync();
		target.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
		await settle();
		expect(calls[0].body).toEqual({ username: 'carl', quota: null, is_admin: false });
		expect(target.textContent).toContain(SECRET);
		// The form that asked is gone: focus is on what replaced it.
		expect(document.activeElement).toBe(target.querySelector('section.once'));
		window.dispatchEvent(new Event('pagehide'));
		flushSync();
		expect(target.textContent).not.toContain(SECRET);
		unmount(app);
	});

	it('forgets a typed password on pagehide', () => {
		server({});
		const { app, target } = open();
		set(target.querySelector('input[name=password]')!, 'typedsecret1');
		flushSync();
		window.dispatchEvent(new Event('pagehide'));
		flushSync();
		expect(target.querySelector<HTMLInputElement>('input[name=password]')!.value).toBe('');
		unmount(app);
	});

	it('asks before making an admin, and makes none if cancelled', async () => {
		const calls = server({ 'POST /api/v1/admin/users': [json(201, { username: 'ada', password: SECRET, is_admin: true })] });
		const { app, target } = open();
		set(target.querySelector('input[name=username]')!, 'ada');
		set(target.querySelector('select[name=is_admin]')!, '1');
		flushSync();
		expect(button(target, 'Create administrator')).toBeDefined();
		target.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
		flushSync();
		button(target, 'Cancel')!.click();
		flushSync();
		expect(calls).toEqual([]);
		target.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
		flushSync();
		armed(target).click();
		await settle();
		expect(calls[0].body).toMatchObject({ username: 'ada', is_admin: true });
		unmount(app);
	});

	it('says why and keeps the form when refused', async () => {
		server({ 'POST /api/v1/admin/users': [json(409, { error: { code: 'username_taken', message: 'A user by that name already exists.' } })] });
		const { app, target } = open();
		set(target.querySelector('input[name=username]')!, 'alice');
		target.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
		await settle();
		expect(target.querySelector('[role=alert]')?.textContent).toBe('A user by that name already exists.');
		expect(document.activeElement).toBe(target.querySelector('[role=alert]'));
		expect(target.querySelector<HTMLInputElement>('input[name=username]')!.value).toBe('alice');
		unmount(app);
	});
});

describe('AdminUserDetail', () => {
	const user = (over: Record<string, unknown> = {}) => ({
		id: 'u1', username: 'bob', is_admin: false, is_active: true, quota: 7, used: 1, must_change_password: false, ...over
	});
	function open(props: Record<string, unknown> = {}) {
		const target = document.createElement('div');
		document.body.append(target);
		const onchanged = vi.fn(async () => {});
		const app = mount(AdminUserDetail, {
			target,
			props: {
				user: user(),
				isSelf: false,
				databases: [{ name: 'bob_db', status: 'active', server_name: 'local' }],
				onchanged,
				profileHref: '/profile',
				dbHref: (n: string) => `/db/${n}`,
				...props
			}
		});
		flushSync();
		return { app, target, onchanged };
	}

	it('keeps a custom quota selected and saves the chosen one', async () => {
		const calls = server({ 'POST /api/v1/admin/users/u1/quota': [json(200, { ok: true })] });
		const { app, target, onchanged } = open();
		const select = target.querySelector<HTMLSelectElement>('select[name=quota]')!;
		expect(select.value).toBe('7');
		set(select, 'unlimited');
		flushSync();
		target.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
		await settle();
		expect(calls[0].body).toEqual({ quota: null });
		expect(target.querySelector('[role=status]')?.textContent).toBe('Quota updated.');
		expect(onchanged).toHaveBeenCalledOnce();
		unmount(app);
	});

	it('suspends only after confirming', async () => {
		const calls = server({ 'POST /api/v1/admin/users/u1/active': [json(200, { ok: true })] });
		const { app, target } = open();
		button(target, 'Suspend…')!.click();
		flushSync();
		button(target, 'Cancel')!.click();
		flushSync();
		expect(calls).toEqual([]);
		button(target, 'Suspend…')!.click();
		flushSync();
		armed(target).click();
		await settle();
		expect(calls[0]).toEqual({ key: 'POST /api/v1/admin/users/u1/active', body: { active: false } });
		// The button that opened the dialog was disabled meanwhile (and becomes
		// Enable): focus is on what happened, not the page.
		expect(document.activeElement).toBe(target.querySelector('[role=status]'));
		unmount(app);
	});

	it('shows a reset password once, in place, and forgets it', async () => {
		server({ 'POST /api/v1/admin/users/u1/reset-password': [json(200, { username: 'bob', password: SECRET })] });
		const { app, target } = open();
		button(target, 'Reset password…')!.click();
		flushSync();
		armed(target).click();
		await settle();
		expect(target.textContent).toContain(SECRET);
		expect(document.activeElement).toBe(target.querySelector('section.once'));
		button(target, "Done — I've passed it on")!.click();
		flushSync();
		expect(target.textContent).not.toContain(SECRET);
		unmount(app);
	});

	it('forgets a reset password on pagehide', async () => {
		server({ 'POST /api/v1/admin/users/u1/reset-password': [json(200, { username: 'bob', password: SECRET })] });
		const { app, target } = open();
		button(target, 'Reset password…')!.click();
		flushSync();
		armed(target).click();
		await settle();
		expect(target.textContent).toContain(SECRET);
		window.dispatchEvent(new Event('pagehide'));
		flushSync();
		expect(target.textContent).not.toContain(SECRET);
		unmount(app);
	});

	it('lands focus on a refusal after the dialog closes', async () => {
		server({ 'POST /api/v1/admin/users/u1/active': [json(409, { error: { code: 'last_admin', message: 'The last active administrator cannot be suspended.' } })] });
		const { app, target } = open();
		button(target, 'Suspend…')!.click();
		flushSync();
		armed(target).click();
		await settle();
		const alert = target.querySelector('[role=alert]');
		expect(alert?.textContent).toBe('The last active administrator cannot be suspended.');
		expect(document.activeElement).toBe(alert);
		unmount(app);
	});

	it('offers nothing on your own account but the profile', () => {
		server({});
		const { app, target } = open({ isSelf: true });
		expect(button(target, 'Suspend…')).toBeUndefined();
		expect(button(target, 'Reset password…')).toBeUndefined();
		expect(target.querySelector<HTMLAnchorElement>('a[href="/profile"]')).not.toBeNull();
		expect(button(target, 'Save')).toBeDefined(); // PRECONDITION: the page rendered
		unmount(app);
	});

	it('links each database to its page', () => {
		server({});
		const { app, target } = open();
		expect(target.querySelector<HTMLAnchorElement>('a[href="/db/bob_db"]')?.textContent).toBe('bob_db');
		unmount(app);
	});
});
