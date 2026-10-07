import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('$app/paths', () => ({
	resolve: (id: string, params: Record<string, string> = {}) =>
		id.replace(/\/\([^)]+\)/g, '').replace(/\[(\w+)\]/g, (_: string, k: string) => params[k]) || '/'
}));
const { default: Page } = await import('./+page.svelte');

const PASSWORD = 'S3cretShownExactlyOnce0000000000';
const server = { id: 's1', name: 'local', engine: 'postgres', default_cidr: null, sources: [] };
const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const settle = () => new Promise((r) => setTimeout(r, 0)).then(() => flushSync());

let target: HTMLElement;
function render(servers: unknown[], respond?: () => Response) {
	if (respond) vi.stubGlobal('fetch', vi.fn(async () => respond()));
	target = document.createElement('div');
	document.body.append(target);
	const app = mount(Page, { target, props: { data: { servers } } as never });
	flushSync();
	return app;
}
afterEach(() => {
	vi.unstubAllGlobals();
	target.remove();
});

async function provision() {
	const name = target.querySelector<HTMLInputElement>('input[name=name]')!;
	name.value = 'alice_app';
	name.dispatchEvent(new Event('input'));
	target.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
	await settle();
	await settle();
}

describe('provisioning', () => {
	it('replaces the form with the credentials, focused, and links to the database', async () => {
		const app = render([server], () =>
			json(201, { name: 'alice_app', username: 'alice_app', password: PASSWORD, conn: 'c', via: [], warnings: [] })
		);
		expect(target.querySelector('h1')?.textContent).toBe('New database');
		await provision();
		expect(target.querySelector('h1')?.textContent).toBe('Database ready');
		expect(target.querySelector('form')).toBeNull();
		expect(target.textContent).toContain(PASSWORD);
		expect(document.activeElement).toBe(target.querySelector('section.once'));
		const open = [...target.querySelectorAll('a')].find((a) => a.textContent === 'Open the database');
		expect(open?.getAttribute('href')).toBe('/db/alice_app/connect');
		unmount(app);
	});

	it('forgets the password when the page is hidden', async () => {
		const app = render([server], () =>
			json(201, { name: 'alice_app', username: 'alice_app', password: PASSWORD, conn: 'c', via: [], warnings: [] })
		);
		await provision();
		expect(target.textContent).toContain(PASSWORD);
		window.dispatchEvent(new Event('pagehide'));
		flushSync();
		expect(target.textContent).not.toContain(PASSWORD);
		unmount(app);
	});

	it('shows an edge that did not take the new database as a warning above the credentials', async () => {
		const app = render([server], () =>
			json(201, { name: 'alice_app', username: 'alice_app', password: PASSWORD, conn: 'c', via: [], warnings: ['Edge sync FAILED'] })
		);
		await provision();
		expect(target.querySelector('[role=alert]')?.textContent).toBe('Edge sync FAILED');
		expect(target.textContent).toContain(PASSWORD);
		unmount(app);
	});

	it('keeps the form and says why when the server refuses', async () => {
		const app = render([server], () => json(409, { error: { code: 'quota', message: 'Quota reached (3 of 3).' } }));
		await provision();
		expect(target.querySelector('[role=alert]')?.textContent).toBe('Quota reached (3 of 3).');
		expect(target.querySelector<HTMLInputElement>('input[name=name]')?.value).toBe('alice_app');
		unmount(app);
	});

	it('with no server configured, says provisioning is unavailable and offers no form', () => {
		const app = render([]);
		expect(target.querySelector('#no-servers h2')?.textContent).toBe('Provisioning is unavailable');
		expect(target.querySelector('form')).toBeNull();
		unmount(app);
	});

	it('sends what the form holds: the server, the name, the ticked sources and the typed ranges', async () => {
		const lan = { id: 'src-lan', label: 'lan', cidr: '192.168.8.0/24', is_default: true };
		const vpn = { id: 'src-vpn', label: 'vpn', cidr: '10.8.0.0/16', is_default: false };
		const withSources = { id: 's1', name: 'local', engine: 'postgres', default_cidr: '172.18.0.0/16', sources: [lan, vpn] };
		const bare = { id: 's2', name: 'nas', engine: 'postgres', default_cidr: '10.0.0.0/8', sources: [] };
		const bodies: unknown[] = [];
		vi.stubGlobal('fetch', vi.fn(async (_: string, init?: RequestInit) => {
			bodies.push(JSON.parse(String(init?.body)));
			return json(201, { name: 'alice_app', username: 'alice_app', password: PASSWORD, conn: 'c', via: [], warnings: [] });
		}));
		target = document.createElement('div');
		document.body.append(target);
		const app = mount(Page, { target, props: { data: { servers: [withSources, bare] } } as never });
		flushSync();
		// On the first server: its default source is ticked, the field is empty.
		const box = (label: string) => [...target.querySelectorAll('label.check')].find((l) => l.textContent?.includes(label))!.querySelector('input')!;
		expect(box('lan').checked).toBe(true);
		box('vpn').click();
		flushSync();
		// Switching away and back resets the ticks to that server's defaults,
		// and the field follows the server's default range while untouched.
		const select = target.querySelector<HTMLSelectElement>('select[name=server_id]')!;
		select.value = 's2';
		select.dispatchEvent(new Event('change', { bubbles: true }));
		flushSync();
		expect(target.querySelector<HTMLInputElement>('input[name=allowed_from]')!.value).toBe('10.0.0.0/8');
		select.value = 's1';
		select.dispatchEvent(new Event('change', { bubbles: true }));
		flushSync();
		expect(target.querySelector<HTMLInputElement>('input[name=allowed_from]')!.value).toBe('');
		box('vpn').click();
		flushSync();
		const field = target.querySelector<HTMLInputElement>('input[name=allowed_from]')!;
		field.value = '10.10.12.33';
		field.dispatchEvent(new Event('input'));
		await provision();
		expect(bodies).toEqual([
			{ server_id: 's1', name: 'alice_app', allowed_from: '10.10.12.33', sources: ['src-lan', 'src-vpn'] }
		]);
		unmount(app);
	});
});
