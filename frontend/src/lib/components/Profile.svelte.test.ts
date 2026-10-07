import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import Profile from './Profile.svelte';

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const sess = (current: boolean) => ({ created_at: '2026-10-07T09:00:00Z', last_seen: '2026-10-07T10:00:00Z', current });
const SESSIONS = 'GET /api/v1/me/sessions';
const CHANGE = 'POST /api/v1/me/password';
const REVOKE = 'POST /api/v1/me/sessions/revoke-others';

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

async function open(must_change_password = false) {
	const target = document.createElement('div');
	document.body.append(target);
	const onchanged = vi.fn(async () => {});
	const app = mount(Profile, {
		target,
		props: { me: { username: 'alice', is_admin: false, must_change_password }, onchanged }
	});
	await settle();
	return { app, target, onchanged };
}
function fill(t: HTMLElement, current: string, next: string, confirm: string) {
	for (const [name, v] of [['current_password', current], ['new_password', next], ['confirm_password', confirm]]) {
		const i = t.querySelector<HTMLInputElement>(`input[name=${name}]`)!;
		i.value = v;
		i.dispatchEvent(new Event('input'));
	}
	flushSync();
}
const submit = (t: HTMLElement) => t.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));

afterEach(() => {
	vi.unstubAllGlobals();
	document.body.innerHTML = '';
});

describe('Profile', () => {
	it('changes the password, forgets what was typed, and re-reads the account', async () => {
		const calls = server({
			[SESSIONS]: [json(200, { sessions: [sess(true), sess(false)] }), json(200, { sessions: [sess(true)] })],
			[CHANGE]: [json(200, { other_sessions_signed_out: 1 })]
		});
		const { app, target, onchanged } = await open();
		fill(target, 'oldpassword', 'newpassword1', 'newpassword1');
		submit(target);
		await settle();
		await settle();
		expect(calls.find((c) => c.key === CHANGE)?.body).toEqual({
			current_password: 'oldpassword',
			new_password: 'newpassword1',
			confirm_password: 'newpassword1'
		});
		expect(target.querySelector('[role=status]')?.textContent).toContain('Password changed');
		for (const i of target.querySelectorAll<HTMLInputElement>('input[type=password]')) expect(i.value).toBe('');
		expect(onchanged).toHaveBeenCalledOnce();
		expect(target.querySelectorAll('tbody tr')).toHaveLength(1);
		unmount(app);
	});

	it('shows a refusal in the server’s words and keeps nothing changed on screen', async () => {
		server({
			[SESSIONS]: [json(200, { sessions: [sess(true)] })],
			[CHANGE]: [json(403, { error: { code: 'wrong_password', message: 'Current password is wrong.' } })]
		});
		const { app, target, onchanged } = await open();
		fill(target, 'nope', 'newpassword1', 'newpassword1');
		submit(target);
		await settle();
		expect(target.querySelector('[role=alert]')?.textContent).toBe('Current password is wrong.');
		expect(target.querySelector('[role=status]')).toBeNull();
		expect(onchanged).not.toHaveBeenCalled();
		// Kept so it can be corrected — but not into the back/forward cache.
		const fields = () => [...target.querySelectorAll<HTMLInputElement>('input[type=password]')].map((i) => i.value);
		expect(fields()).toEqual(['nope', 'newpassword1', 'newpassword1']);
		window.dispatchEvent(new Event('pagehide'));
		flushSync();
		expect(fields()).toEqual(['', '', '']);
		unmount(app);
	});

	it('sends one change however fast it is submitted', async () => {
		let release!: (r: Response) => void;
		const calls = server({
			[SESSIONS]: [json(200, { sessions: [sess(true)] }), json(200, { sessions: [sess(true)] })],
			[CHANGE]: [new Promise<Response>((r) => (release = r))]
		});
		const { app, target } = await open();
		fill(target, 'oldpassword', 'newpassword1', 'newpassword1');
		submit(target);
		submit(target);
		release(json(200, { other_sessions_signed_out: 0 }));
		await settle();
		expect(calls.filter((c) => c.key === CHANGE)).toHaveLength(1);
		unmount(app);
	});

	it('says why it is there when the password is an admin’s', async () => {
		server({ [SESSIONS]: [json(200, { sessions: [sess(true)] })] });
		const { app, target } = await open(true);
		expect(target.querySelector('[role=alert]')?.textContent).toContain('set by an administrator');
		unmount(app);
		const plain = await open(false);
		expect(plain.target.textContent).not.toContain('set by an administrator');
		unmount(plain.app);
	});

	it('signs out the others, offered only when there are others', async () => {
		const calls = server({
			[SESSIONS]: [json(200, { sessions: [sess(true), sess(false), sess(false)] }), json(200, { sessions: [sess(true)] })],
			[REVOKE]: [json(200, { signed_out: 2 })]
		});
		const { app, target } = await open();
		// Which row is this one, said in words on that row only.
		const marks = [...target.querySelectorAll('#sessions tbody tr')].map((r) => r.querySelector('.badge')?.textContent ?? null);
		expect(marks).toEqual(['This session', null, null]);
		expect(target.querySelector('#session-count')?.textContent?.trim()).toMatch(/^3 sessions, this one included\./);
		const button = () => [...target.querySelectorAll('button')].find((b) => b.textContent === 'Sign out everywhere else');
		button()!.click();
		await settle();
		await settle();
		expect(calls.map((c) => c.key)).toEqual([SESSIONS, REVOKE, SESSIONS]);
		expect(target.querySelector('[role=status]')?.textContent).toBe('Signed out 2 other session(s).');
		expect(button()).toBeUndefined();
		expect(target.querySelector('#session-count')?.textContent?.trim()).toBe('Only here.');
		unmount(app);
	});
});
