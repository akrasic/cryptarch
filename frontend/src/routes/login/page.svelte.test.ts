import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';

const nav = vi.hoisted(() => ({ goto: vi.fn(async () => {}) }));
vi.mock('$app/navigation', () => nav);
vi.mock('$app/paths', () => ({
	resolve: (id: string) => id.replace(/\/\([^)]+\)/g, '') || '/'
}));
const { default: Page } = await import('./+page.svelte');

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const settle = () => new Promise((r) => setTimeout(r, 0)).then(() => flushSync());

let target: HTMLElement;
function open(respond: () => Response | Promise<Response>) {
	const fetch = vi.fn(async () => respond());
	vi.stubGlobal('fetch', fetch);
	target = document.createElement('div');
	document.body.append(target);
	const app = mount(Page, { target });
	flushSync();
	return { app, fetch };
}
function type(name: string, value: string) {
	const input = target.querySelector<HTMLInputElement>(`input[name=${name}]`)!;
	input.value = value;
	input.dispatchEvent(new Event('input'));
}
const submit = () => target.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
afterEach(() => {
	vi.unstubAllGlobals();
	nav.goto.mockClear();
	target.remove();
});

describe('signing in', () => {
	it('sends what was typed and goes to your databases', async () => {
		const { app, fetch } = open(() => json(200, { username: 'alice', is_admin: false, must_change_password: false }));
		type('username', 'alice');
		type('password', 'hunter2hunter2');
		submit();
		await settle();
		const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
		expect([url, init.method, JSON.parse(String(init.body))]).toEqual(['/api/v1/session', 'POST', { username: 'alice', password: 'hunter2hunter2' }]);
		expect(nav.goto).toHaveBeenCalledWith('/dashboard');
		unmount(app);
	});

	it('shows a refusal in the server\'s words, focused, keeps the name and forgets the password', async () => {
		const { app } = open(() => json(401, { error: { code: 'bad_credentials', message: 'Wrong username or password.' } }));
		type('username', 'alice');
		type('password', 'nope');
		submit();
		await settle();
		await settle();
		const alert = target.querySelector('[role=alert]');
		expect(alert?.textContent).toBe('Wrong username or password.');
		expect(document.activeElement).toBe(alert);
		expect(target.querySelector<HTMLInputElement>('input[name=username]')!.value).toBe('alice');
		expect(target.querySelector<HTMLInputElement>('input[name=password]')!.value).toBe('');
		expect(nav.goto).not.toHaveBeenCalled();
		unmount(app);
	});

	it('says it is signing in while it does, and sends one request however often it is submitted', async () => {
		let release!: (r: Response) => void;
		const { app, fetch } = open(() => new Promise<Response>((r) => (release = r)));
		type('username', 'alice');
		type('password', 'pw');
		submit();
		flushSync();
		const button = target.querySelector<HTMLButtonElement>('button[type=submit]')!;
		expect([button.textContent, button.disabled]).toEqual(['Signing in…', true]);
		// A second submit while the first is on its way (Enter, not the button).
		submit();
		release(json(200, {}));
		await settle();
		expect(fetch).toHaveBeenCalledOnce();
		unmount(app);
	});

	it('never keeps a typed password into the back/forward cache', () => {
		const { app } = open(() => json(500, {}));
		type('username', 'alice');
		type('password', 'typed-not-sent');
		flushSync();
		// Premise: it was there.
		expect(target.querySelector<HTMLInputElement>('input[name=password]')!.value).toBe('typed-not-sent');
		window.dispatchEvent(new Event('pagehide'));
		flushSync();
		expect(target.querySelector<HTMLInputElement>('input[name=password]')!.value).toBe('');
		expect(target.querySelector<HTMLInputElement>('input[name=username]')!.value).toBe('alice');
		unmount(app);
	});
});
