// The app shell (CRYPTARCH-151): the rail's wiring from page data, the phone
// drawer's focus and closing rules, and sign-out's ordering.
import { createRawSnippet, flushSync, mount, tick, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const nav = vi.hoisted(() => ({ goto: vi.fn(async () => {}), afterNavigate: vi.fn() }));
const page = vi.hoisted(() => ({
	route: { id: '/(app)/db/[name]/access' as string },
	url: new URL('http://x/db/eddy/access'),
	data: {} as Record<string, unknown>
}));
vi.mock('$app/navigation', () => nav);
vi.mock('$app/state', () => ({ page }));
vi.mock('$app/paths', () => ({
	resolve: (id: string, params: Record<string, string> = {}) =>
		id.replace(/\/\([^)]+\)/g, '').replace(/\[(\w+)\]/g, (_: string, k: string) => params[k]) || '/'
}));

const { default: Layout } = await import('./+layout.svelte');
const { setNotice, takeNotice } = await import('#lib/notice.svelte.js');

const db = { name: 'eddy', status: 'deleting', server_name: 'local', engine: 'postgres', is_owner: true };
const me = { username: 'alice', is_admin: false, must_change_password: false };

let target: HTMLElement;
let app: ReturnType<typeof mount> | null = null;
let fetchMock: ReturnType<typeof vi.fn>;

function render() {
	target = document.createElement('div');
	document.body.append(target);
	const children = createRawSnippet(() => ({ render: () => '<p class="page-body">body</p>' }));
	app = mount(Layout, { target, props: { data: { me }, children } as never });
	flushSync();
}

beforeEach(() => {
	page.route.id = '/(app)/db/[name]/access';
	page.url = new URL('http://x/db/eddy/access');
	page.data = { db };
	nav.goto.mockClear();
	nav.afterNavigate.mockClear();
	fetchMock = vi.fn();
	vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
	if (app) unmount(app);
	app = null;
	target.remove();
	vi.unstubAllGlobals();
});

const rail = () => target.querySelector('.shell-side')!;
const drawer = () => document.querySelector('.drawer');
// jsdom keeps `inert` as a property only; a browser reflects it to the
// attribute (the smoke checks that side).
const inert = () => (target.querySelector('.shell') as HTMLElement & { inert?: boolean }).inert === true;

describe('the shell', () => {
	it('draws the rail from the page data: the database it is inside and the section', () => {
		render();
		expect(rail().querySelector('.side-scope-name')?.textContent).toContain('eddy');
		expect(rail().querySelector('a.side-item[aria-current]')?.textContent).toBe('Access');
		expect(target.querySelector('.page-body')).not.toBeNull();
	});

	it('keeps the status in sight on a phone, in the switcher', () => {
		render();
		const sw = target.querySelector<HTMLButtonElement>('button.switcher')!;
		expect(sw.querySelector('.badge')?.textContent).toBe('Deleting');
		expect(sw.getAttribute('aria-label')).toBe('eddy, deleting, Access. Open sections');
	});

	it('has no switcher outside a database or server', () => {
		// Premise: the switcher renders inside one (above).
		page.route.id = '/(app)/dashboard';
		page.url = new URL('http://x/dashboard');
		page.data = {};
		render();
		expect(rail().querySelector('a.side-item[aria-current]')?.textContent).toBe('Databases');
		expect(target.querySelector('button.switcher')).toBeNull();
	});
});

describe('the phone drawer', () => {
	async function open(from = 'button.menu-btn') {
		const opener = target.querySelector<HTMLButtonElement>(from)!;
		opener.focus();
		opener.click();
		await tick();
		await tick();
		return opener;
	}

	it('takes focus to the current section and makes the page behind it inert', async () => {
		render();
		expect(inert()).toBe(false);
		await open();
		expect(drawer()).not.toBeNull();
		expect(document.activeElement?.textContent).toBe('Access');
		expect(drawer()!.contains(document.activeElement)).toBe(true);
		expect(inert()).toBe(true);
		expect(target.querySelector('button.menu-btn')?.getAttribute('aria-expanded')).toBe('true');
	});

	it('closes on Escape and gives focus back to what opened it', async () => {
		render();
		const opener = await open('button.switcher');
		window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
		flushSync();
		expect(drawer()).toBeNull();
		expect(inert()).toBe(false);
		expect(document.activeElement).toBe(opener);
	});

	it('closes on the backdrop', async () => {
		render();
		await open();
		document.querySelector<HTMLElement>('.drawer-scrim')!.click();
		flushSync();
		expect(drawer()).toBeNull();
	});

	it('closes after any navigation', async () => {
		render();
		await open();
		expect(nav.afterNavigate).toHaveBeenCalledOnce();
		(nav.afterNavigate.mock.calls[0] as unknown as [() => void])[0]();
		flushSync();
		expect(drawer()).toBeNull();
	});
});

describe('signing out', () => {
	const respond = (status: number, body?: unknown) =>
		fetchMock.mockResolvedValueOnce(
			new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
		);
	const signOut = async () => {
		rail().querySelector<HTMLButtonElement>('button.side-signout')!.click();
		await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledOnce());
		await tick();
		await tick();
	};

	it('ends the session on the server first, then leaves, taking any notice with it', async () => {
		respond(204);
		setNotice({ message: 'alice_db deleted' });
		render();
		await signOut();
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect([init.method, url]).toEqual(['DELETE', '/api/v1/session']);
		await vi.waitFor(() => expect(nav.goto).toHaveBeenCalledWith('/login'));
		expect(takeNotice()).toBeNull();
	});

	it('stays signed in, and says so, when the server did not end the session', async () => {
		respond(500, { error: { code: 'internal', message: 'Database unavailable.' } });
		render();
		await signOut();
		await vi.waitFor(() => expect(rail().querySelector('[role="alert"]')?.textContent).toBe('Database unavailable.'));
		expect(nav.goto).not.toHaveBeenCalled();
	});

	it('treats a session already gone as signed out', async () => {
		respond(401, { error: { code: 'unauthenticated', message: 'Sign in.' } });
		render();
		await signOut();
		await vi.waitFor(() => expect(nav.goto).toHaveBeenCalledWith('/login'));
	});
});
