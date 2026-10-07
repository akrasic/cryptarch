import { flushSync, mount, unmount, type Component } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Server } from '#lib/admin-servers.js';
import ServerListeners from './ServerListeners.svelte';
import ServerPools from './ServerPools.svelte';
import ServerSettings from './ServerSettings.svelte';
import ServerSources from './ServerSources.svelte';

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const fail = (status: number, code: string, message: string) => json(status, { error: { code, message } });
const applied = { state: 'applied', rules: 3, hba: null, knobs: null, error: null };

let sent: { key: string; body: unknown }[] = [];
function api(routes: Record<string, Response[]>) {
	sent = [];
	vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
		const key = `${init?.method ?? 'GET'} ${url}`;
		sent.push({ key, body: init?.body ? JSON.parse(init.body as string) : undefined });
		const next = routes[key]?.shift();
		if (!next) throw new Error(`unexpected ${key}`);
		return next;
	}));
}
async function settle() {
	await vi.advanceTimersByTimeAsync(0);
	flushSync();
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mountIn<P extends Record<string, any>>(C: Component<P>, props: Omit<P, 'onchanged'>) {
	const target = document.createElement('div');
	document.body.append(target);
	const onchanged = vi.fn(async () => {});
	const app = mount(C, { target, props: { ...props, onchanged } as unknown as P });
	flushSync();
	return { app, target, onchanged };
}
function type(t: ParentNode, sel: string, value: string) {
	const el = t.querySelector(sel) as HTMLInputElement | HTMLSelectElement;
	el.value = value;
	el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
}
const button = (t: ParentNode, text: string, label?: string) =>
	[...t.querySelectorAll('button')].find((b) => b.textContent?.trim() === text && (!label || b.getAttribute('aria-label') === label));
const val = (t: ParentNode, sel: string) => (t.querySelector(sel) as HTMLInputElement).value;

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllGlobals();
	document.body.innerHTML = '';
});

describe('ServerPools', () => {
	const POOL = 'POST /api/v1/admin/servers/s1/databases/d1/pool';
	const dbs = [{ id: 'd1', name: 'alice_db', status: 'active', pool_mode: 'session', max_connections: 5 }];

	it('starts from what is stored, sends inherit and an empty limit as such, and says what the edge did', async () => {
		api({ [POOL]: [json(200, { name: 'alice_db', edge: applied }), json(200, { name: 'alice_db', edge: { ...applied, state: 'failed', error: 'no reload' } })] });
		const { app, target, onchanged } = mountIn(ServerPools, { serverId: 's1', poolMode: 'transaction', maxUserConnections: 0, databases: dbs });
		expect(val(target, 'select[name=pool_mode]')).toBe('session');
		expect(val(target, 'input[name=max_connections]')).toBe('5');
		type(target, 'select[name=pool_mode]', 'inherit');
		type(target, 'input[name=max_connections]', '');
		button(target, 'Apply')!.click();
		await settle();
		expect(sent[0].body).toEqual({ pool_mode: 'inherit', max_connections: null });
		expect(target.querySelector('[role=status]')!.textContent).toBe('Override for alice_db saved — edge synced.');
		expect(onchanged).toHaveBeenCalledTimes(1);
		button(target, 'Apply')!.click();
		await settle();
		expect(target.querySelector('[role=alert]')!.textContent).toContain('edge sync FAILED: no reload');
		expect(target.querySelector('[role=status]')).toBeNull();
		unmount(app);
	});

	it('refuses a limit that is not a number, rather than sending it as inherit', async () => {
		api({ [POOL]: [fail(404, 'no_such_item', 'That is not on this server.')] });
		const { app, target, onchanged } = mountIn(ServerPools, { serverId: 's1', poolMode: 'session', maxUserConnections: 0, databases: dbs });
		type(target, 'input[name=max_connections]', '1e');
		button(target, 'Apply')!.click();
		await settle();
		expect(sent).toEqual([]);
		expect(target.querySelector('[role=alert]')!.textContent).toContain('whole number');
		expect(document.activeElement).toBe(target.querySelector('[role=alert]'));
		type(target, 'input[name=max_connections]', ' 12 ');
		button(target, 'Apply')!.click();
		await settle();
		expect(sent[0].body).toEqual({ pool_mode: 'session', max_connections: 12 });
		expect(onchanged).toHaveBeenCalledTimes(1);
		unmount(app);
	});
});

describe('ServerSources', () => {
	const BASE = 'POST /api/v1/admin/servers/s1/sources';
	const sources = [{ id: 'x1', label: 'lan', cidr: '192.168.8.0/24', is_default: true }];

	it('adds one, clearing the form', async () => {
		api({ [BASE]: [json(201, { ok: true })] });
		const { app, target, onchanged } = mountIn(ServerSources, { serverId: 's1', sources: [] });
		type(target, 'input[name=source_label]', 'tailnet');
		type(target, 'input[name=source_cidr]', '100.64.0.0/10');
		type(target, 'select[name=source_default]', '1');
		(target.querySelector('form') as HTMLFormElement).requestSubmit();
		await settle();
		expect(sent[0].body).toEqual({ label: 'tailnet', cidr: '100.64.0.0/10', is_default: true });
		expect(val(target, 'input[name=source_label]')).toBe('');
		expect(onchanged).toHaveBeenCalledTimes(1);
		unmount(app);
	});

	it('removes only after the confirm, and reloads when it was already gone', async () => {
		api({ 'DELETE /api/v1/admin/servers/s1/sources/x1': [fail(404, 'no_such_item', 'That is not on this server.')] });
		const { app, target, onchanged } = mountIn(ServerSources, { serverId: 's1', sources });
		button(target, 'Remove')!.click();
		flushSync();
		expect(document.querySelector('.dialog')!.textContent).toContain('Access already granted from it stays');
		button(document.body, 'Cancel')!.click();
		flushSync();
		expect(sent).toEqual([]);
		button(target, 'Remove')!.click();
		flushSync();
		document.querySelector<HTMLButtonElement>('.dialog button.btn-danger-solid')!.click();
		await settle();
		expect(sent.map((x) => x.key)).toEqual(['DELETE /api/v1/admin/servers/s1/sources/x1']);
		expect(target.querySelector('[role=alert]')!.textContent).toBe('That is not on this server.');
		expect(document.activeElement).toBe(target.querySelector('[role=alert]'));
		expect(onchanged).toHaveBeenCalledTimes(1);
		unmount(app);
	});
});

describe('ServerListeners', () => {
	it('shows the primary first, adds with a numeric port, removes after a confirm', async () => {
		api({
			'POST /api/v1/admin/servers/s1/listeners': [json(201, { ok: true })],
			'DELETE /api/v1/admin/servers/s1/listeners/l1': [json(200, { ok: true })]
		});
		const { app, target, onchanged } = mountIn(ServerListeners, {
			serverId: 's1', primary: 'pg.lan:6432', listeners: [{ id: 'l1', label: 'tailnet', host: 'pg.ts', port: 6432 }]
		});
		expect(target.querySelector('#listeners-list tbody tr')!.textContent).toContain('pg.lan:6432');
		type(target, 'input[name=listener_label]', 'public');
		type(target, 'input[name=listener_host]', 'pg.example.com');
		type(target, 'input[name=listener_port]', '16432');
		(target.querySelector('form') as HTMLFormElement).requestSubmit();
		await settle();
		expect(sent[0].body).toEqual({ label: 'public', host: 'pg.example.com', port: 16432 });
		button(target, 'Remove', 'Remove listener tailnet')!.click();
		flushSync();
		document.querySelector<HTMLButtonElement>('.dialog button.btn-danger-solid')!.click();
		await settle();
		expect(sent[1].key).toBe('DELETE /api/v1/admin/servers/s1/listeners/l1');
		expect(target.querySelector('[role=status]')!.textContent).toBe('Listener tailnet removed.');
		// The row and its button are gone: focus is on what happened.
		expect(document.activeElement).toBe(target.querySelector('[role=status]'));
		expect(onchanged).toHaveBeenCalledTimes(2);
		unmount(app);
	});
});

describe('ServerSettings', () => {
	const server = {
		id: 's1', name: 'pg-main', engine: 'postgres', host: 'pg.lan', port: 6432, is_active: true, pool_mode: 'session',
		default_pool_size: 20, max_client_conn: 100, max_db_connections: 0, max_user_connections: 5, tls_mode: 'off',
		backend_kind: 'docker', default_consumer_cidr: '10.0.0.0/8', has_admin_dsn: true, has_bouncer_dsn: false, db_count: 0,
		init_status: 'ready', bouncer_conf_dir: null, edge_dirty: false, edge_synced_at: null, status: 'active', health: null
	} satisfies Server;
	const P = 'POST /api/v1/admin/servers/s1/settings';

	it('starts from the row and sends each card on its own, as numbers and nulls', async () => {
		api({
			[`${P}/address`]: [json(200, { reconnected: false })],
			[`${P}/pooling`]: [json(200, { edge: applied })],
			[`${P}/edge`]: [json(200, { edge: { ...applied, state: 'manual' } })]
		});
		const { app, target, onchanged } = mountIn(ServerSettings, { server, listenersHref: '/admin/servers/s1/listeners' });
		expect(val(target, 'input[name=host]')).toBe('pg.lan');
		expect(val(target, 'input[name=max_user_connections]')).toBe('5');
		expect(val(target, 'input[name=default_consumer_cidr]')).toBe('10.0.0.0/8');

		type(target, 'input[name=port]', '7432');
		(target.querySelector('#address-form') as HTMLFormElement).requestSubmit();
		await settle();
		expect(sent[0].body).toEqual({ host: 'pg.lan', port: 7432 });
		expect(target.querySelector('[role=alert]')!.textContent).toContain('could not reconnect');

		type(target, 'select[name=pool_mode]', 'transaction');
		(target.querySelector('#pooling-form') as HTMLFormElement).requestSubmit();
		await settle();
		expect(sent[1].body).toEqual({ pool_mode: 'transaction', default_pool_size: 20, max_client_conn: 100, max_db_connections: 0, max_user_connections: 5 });
		expect(target.querySelector('[role=status]')!.textContent).toBe('Pooling saved — edge synced.');

		type(target, 'input[name=default_consumer_cidr]', '  ');
		(target.querySelector('#edge-form') as HTMLFormElement).requestSubmit();
		await settle();
		expect(sent[2].body).toEqual({ tls_mode: 'off', backend_kind: 'docker', default_consumer_cidr: null, bouncer_conf_dir: null });
		expect(target.querySelector('[role=status]')!.textContent).toContain('manual placement');
		expect(onchanged).toHaveBeenCalledTimes(3);
		unmount(app);
	});

	it('keeps what is typed in one card when another saves and the row reloads', async () => {
		api({ [`${P}/pooling`]: [json(200, { edge: applied })] });
		const target = document.createElement('div');
		document.body.append(target);
		const props = $state({ server, listenersHref: '/admin/servers/s1/listeners', onchanged: async () => {} });
		props.onchanged = async () => { props.server = { ...server, pool_mode: 'transaction' }; };
		const app = mount(ServerSettings, { target, props });
		flushSync();
		type(target, 'input[name=host]', 'typed.but.unsaved');
		type(target, 'select[name=pool_mode]', 'transaction');
		(target.querySelector('#pooling-form') as HTMLFormElement).requestSubmit();
		await settle();
		expect(target.querySelector('[role=status]')!.textContent).toBe('Pooling saved — edge synced.');
		expect(val(target, 'input[name=host]')).toBe('typed.but.unsaved');
		unmount(app);
	});
});
