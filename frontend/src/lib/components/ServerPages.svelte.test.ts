import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Edge, Overview, Server } from '#lib/admin-servers.js';
import AdminServers from './AdminServers.svelte';
import ServerEdge from './ServerEdge.svelte';
import ServerMaintenance from './ServerMaintenance.svelte';
import ServerOverview from './ServerOverview.svelte';

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const server = (over: Partial<Server> = {}): Server => ({
	id: 's1', name: 'pg-main', engine: 'postgres', host: 'pg.lan', port: 6432, is_active: true,
	pool_mode: 'transaction', default_pool_size: 20, max_client_conn: 100, max_db_connections: 0, max_user_connections: 0,
	tls_mode: 'off', backend_kind: 'docker', default_consumer_cidr: null, has_admin_dsn: true, has_bouncer_dsn: false,
	db_count: 2, init_status: 'ready', bouncer_conf_dir: null, edge_dirty: false, edge_synced_at: null,
	status: 'active', health: null, ...over
});
const overview = (over: Partial<Overview> = {}): Overview => ({
	dashboard: {
		version: '17.5 (Debian)', uptime_secs: 100, uptime: '3d 4h', total_connections: 12, max_connections: 100,
		databases: [
			{ name: 'alice_db', size_bytes: 2048, connections: 1, managed: true },
			{ name: 'legacy', size_bytes: 1024, connections: 0, managed: false }
		]
	},
	maintenance: { findings: [] },
	...over
});
const edge = (over: Partial<Edge> = {}): Edge => ({
	dirty: false, synced_at: null,
	hba: { verdict: 'no conf dir — manual placement mode', state: 'unknown' },
	knobs: { verdict: 'no conf dir — manual placement mode', state: 'unknown' },
	pools: null, ...over
});

const OVERVIEW = 'GET /api/v1/admin/servers/s1/overview';
const EDGE = 'GET /api/v1/admin/servers/s1/edge';
const ACTIVE = 'POST /api/v1/admin/servers/s1/active';
const TEST = 'POST /api/v1/admin/servers/s1/test';

let bodies: Record<string, unknown[]> = {};
function api(routes: Record<string, Response[]>) {
	const calls: string[] = [];
	bodies = {};
	vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
		const key = `${init?.method ?? 'GET'} ${url}`;
		calls.push(key);
		if (init?.body) (bodies[key] ??= []).push(JSON.parse(init.body as string));
		const next = routes[key]?.shift();
		if (!next) throw new Error(`unexpected ${key}`);
		return next;
	}));
	return calls;
}
async function settle() {
	await vi.advanceTimersByTimeAsync(0);
	flushSync();
}
async function mountIn(C: unknown, props: Record<string, unknown>) {
	const target = document.createElement('div');
	document.body.append(target);
	const onchanged = vi.fn(async () => {});
	const app = mount(C as never, { target, props: { onchanged, ...props } as never });
	await settle();
	return { app, target, onchanged };
}
const openOverview = (s: Server = server()) => mountIn(ServerOverview, { server: s, dbHref: (n: string) => `/db/${n}` });
const openMaintenance = () => mountIn(ServerMaintenance, { serverId: 's1' });
const openEdge = (s: Server = server()) => mountIn(ServerEdge, { server: s });
const armed = () => document.querySelector<HTMLButtonElement>('.dialog button.btn-danger-solid')!;
const button = (t: ParentNode, text: string) => [...t.querySelectorAll('button')].find((b) => b.textContent?.trim() === text);
const text = (t: Element, sel: string) => t.querySelector(sel)?.textContent?.replace(/\s+/g, ' ') ?? '';

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllGlobals();
	document.body.innerHTML = '';
});

describe('ServerOverview', () => {
	it('shows the row at once, then asks the server for its databases, and nothing else', async () => {
		const calls = api({ [OVERVIEW]: [json(200, overview())] });
		const { app, target } = await openOverview();
		expect(text(target, '#server-facts')).toContain('Stored (encrypted)');
		expect(calls).toEqual([OVERVIEW]);
		// Cryptarch's own, linked; everything else on the server folded apart.
		const rows = [...target.querySelectorAll('#server-dbs tbody tr')];
		expect(rows.map((r) => r.querySelector('a')?.getAttribute('href'))).toEqual(['/db/alice_db']);
		const external = target.querySelector('#external-dbs')!;
		expect(external.querySelector('summary')!.textContent).toContain("1 other database on this server, not Cryptarch's");
		expect(external.textContent).toContain('legacy');
		expect(external.querySelector('a')).toBeNull();
		expect(target.textContent).toContain('12 / 100');
		unmount(app);
	});

	it('says it could not match its own databases, rather than that it manages none', async () => {
		api({ [OVERVIEW]: [json(200, overview({ dashboard: { ...overview().dashboard!, databases: [{ name: 'legacy', size_bytes: 1, connections: 0, managed: false }] } }))] });
		const blind = await openOverview(server({ db_count: 2 }));
		expect(blind.target.querySelector('#managed-unknown')).not.toBeNull();
		expect(blind.target.querySelector('#no-managed')).toBeNull();
		unmount(blind.app);
		api({ [OVERVIEW]: [json(200, overview({ dashboard: { ...overview().dashboard!, databases: [{ name: 'legacy', size_bytes: 1, connections: 0, managed: false }] } }))] });
		const none = await openOverview(server({ db_count: 0 }));
		expect(none.target.querySelector('#no-managed')).not.toBeNull();
		expect(none.target.querySelector('#managed-unknown')).toBeNull();
		unmount(none.app);
	});

	it('says the dashboard is unavailable when the server did not answer, never shows it empty', async () => {
		api({ [OVERVIEW]: [json(200, { dashboard: null, maintenance: null })] });
		const { app, target } = await openOverview();
		expect(target.querySelector('#dashboard-unavailable')?.textContent).toContain('Server dashboard unavailable');
		expect(target.querySelector('#server-dbs')).toBeNull();
		unmount(app);
	});

	it('drops an answer that was asked for before an enable or disable', async () => {
		let release!: (r: Response) => void;
		const slow = new Promise<Response>((r) => (release = r));
		const calls: string[] = [];
		vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
			const key = `${init?.method ?? 'GET'} ${url}`;
			calls.push(key);
			if (key === OVERVIEW && calls.filter((c) => c === OVERVIEW).length === 1) return slow;
			if (key === OVERVIEW) return json(200, { dashboard: null, maintenance: null });
			if (key === ACTIVE) return json(200, { active: false, connected: null });
			throw new Error(`unexpected ${key}`);
		}));
		const { app, target } = await openOverview();
		button(target, 'Disable…')!.click();
		flushSync();
		armed().click();
		await settle();
		expect(target.textContent).toContain('Server dashboard unavailable');
		release(json(200, overview()));
		await settle();
		expect(target.textContent).toContain('Server dashboard unavailable');
		expect(target.textContent).not.toContain('12 / 100');
		unmount(app);
	});

	it('reports what the server is now, when a disable won the race with an enable', async () => {
		api({ [OVERVIEW]: [json(200, overview()), json(200, overview())], [ACTIVE]: [json(200, { active: false, connected: null })] });
		const { app, target } = await openOverview(server({ is_active: false, status: 'disabled' }));
		button(target, 'Enable')!.click();
		await settle();
		const n = target.querySelector('[role=status]')!.textContent!;
		expect(n).toContain('is disabled');
		expect(n).not.toContain('could not connect');
		unmount(app);
	});

	it('runs server init, shows its report, and reloads the row', async () => {
		const calls = api({
			[OVERVIEW]: [json(200, overview())],
			['POST /api/v1/admin/servers/s1/init']: [json(200, { status: 'needs_bootstrap',
				steps: [{ step: 'Superuser bootstrap', ok: false, detail: 'missing' }], bootstrap_sql: 'GRANT ...', userlist_line: null })]
		});
		const { app, target, onchanged } = await openOverview();
		button(target, 'Run server init')!.click();
		await settle();
		expect(calls).toContain('POST /api/v1/admin/servers/s1/init');
		expect(target.querySelector('#bootstrap-sql')!.textContent).toBe('GRANT ...');
		// On the report itself: not merely somewhere that contains it, like <body>.
		const focused = document.activeElement!;
		expect(focused).not.toBe(document.body);
		expect(target.contains(focused) && focused.contains(target.querySelector('#init-steps'))).toBe(true);
		expect(onchanged).toHaveBeenCalledTimes(1);
		button(target, 'Done')!.click();
		flushSync();
		expect(target.querySelector('#init-steps')).toBeNull();
		unmount(app);
	});

	it('runs the connect test and shows each check', async () => {
		const calls = api({
			[OVERVIEW]: [json(200, overview())],
			[TEST]: [json(200, { checks: [{ check: 'Admin connection', ok: true, detail: 'role ok' }, { check: 'Advertised address', ok: false, detail: 'refused' }] })]
		});
		const { app, target } = await openOverview();
		button(target, 'Run connect test')!.click();
		await settle();
		expect(calls).toContain(TEST);
		const rows = [...target.querySelectorAll('#connect-test tr')];
		expect(rows[0].querySelector('.badge-ok')!.textContent).toBe('role ok');
		expect(rows[1].querySelector('.badge-danger')!.textContent).toBe('refused');
		expect(rows[1].querySelector('.badge-ok')).toBeNull();
		expect(document.activeElement).toBe(target.querySelector('#connect-test')!.closest('section'));
		unmount(app);
	});

	it('disables only after the confirm, then reloads and asks the server again, landing on the answer', async () => {
		const calls = api({
			[OVERVIEW]: [json(200, overview()), json(200, { dashboard: null, maintenance: null })],
			[ACTIVE]: [json(200, { active: false, connected: null })]
		});
		const { app, target, onchanged } = await openOverview();
		button(target, 'Disable…')!.click();
		flushSync();
		expect(document.querySelector('.dialog')!.textContent).toContain('Disable pg-main?');
		button(document.body, 'Cancel')!.click();
		flushSync();
		expect(calls).not.toContain(ACTIVE);
		button(target, 'Disable…')!.click();
		flushSync();
		armed().click();
		await settle();
		expect(bodies[ACTIVE]).toEqual([{ active: false }]);
		expect(target.querySelector('[role=status]')!.textContent).toContain('pg-main is disabled.');
		expect(document.activeElement).toBe(target.querySelector('[role=status]'));
		expect(onchanged).toHaveBeenCalledTimes(1);
		expect(calls.filter((c) => c === OVERVIEW)).toHaveLength(2);
		unmount(app);
	});

	it('says when an enabled server could not be connected, and a refusal in the server\'s words', async () => {
		api({
			[OVERVIEW]: [json(200, overview()), json(200, overview())],
			[ACTIVE]: [json(200, { active: true, connected: false }), json(500, { error: { code: 'internal', message: 'Something went wrong.' } })]
		});
		const { app, target, onchanged } = await openOverview(server({ is_active: false, status: 'disabled' }));
		expect(button(target, 'Disable…')).toBeUndefined();
		button(target, 'Enable')!.click();
		await settle();
		expect(bodies[ACTIVE]).toEqual([{ active: true }]);
		expect(target.querySelector('[role=status]')!.textContent).toContain('could not connect');
		expect(onchanged).toHaveBeenCalledTimes(1);
		button(target, 'Enable')!.click();
		await settle();
		expect(target.querySelector('[role=alert]')!.textContent).toBe('Something went wrong.');
		expect(document.activeElement).toBe(target.querySelector('[role=alert]'));
		expect(onchanged).toHaveBeenCalledTimes(1);
		unmount(app);
	});
});

describe('ServerMaintenance', () => {
	it('says an engine that reports nothing looked at nothing, and a server that did not answer is unavailable', async () => {
		const calls = api({ [OVERVIEW]: [json(200, overview())] });
		const a = await openMaintenance();
		expect(calls).toEqual([OVERVIEW]);
		expect(a.target.textContent).toContain('This engine does not report maintenance checks');
		expect(a.target.querySelector('#maintenance-none')!.classList.contains('empty-blind')).toBe(true);
		unmount(a.app);

		api({ [OVERVIEW]: [json(200, { dashboard: null, maintenance: null })] });
		const b = await openMaintenance();
		expect(b.target.textContent).toContain('Maintenance report unavailable');
		expect(b.target.textContent).not.toContain('does not report maintenance');
		unmount(b.app);
	});

	it('renders findings by severity, an unknown one as urgent', async () => {
		api({
			[OVERVIEW]: [json(200, overview({ maintenance: { findings: [
				{ severity: 'watch', title: 'Bloat', summary: 's1', advice: 'a1' },
				{ severity: 'mystery' as 'ok', title: 'New', summary: 's2', advice: 'a2' },
				{ severity: 'ok', title: 'Headroom', summary: 's3', advice: 'a3' }
			] } }))]
		});
		const { app, target } = await openMaintenance();
		const f = [...target.querySelectorAll('.findings > section')];
		expect(f.map((x) => x.className)).toEqual(['card finding finding-watch', 'card finding finding-urgent', 'card finding finding-ok']);
		expect(f.map((x) => x.querySelector('.badge')!.textContent)).toEqual(['Watch', 'Urgent', 'OK']);
		unmount(app);
	});
});

describe('ServerEdge', () => {
	it('never words silence or a check it could not make as healthy', async () => {
		const calls = api({
			[EDGE]: [json(200, edge({ hba: { verdict: 'hba matches desired ACL state', state: 'ok' },
				knobs: { verdict: 'knobs intact (desired state unavailable)', state: 'unknown' } }))]
		});
		const { app, target } = await openEdge();
		expect(calls).toEqual([EDGE]);
		expect(text(target, '#edge-health')).toContain('No sweep yet');
		const rows = [...target.querySelectorAll('#edge-health .setting')];
		const of = (t: string) => rows.find((d) => d.textContent!.includes(t))!;
		expect(of('No sweep yet').querySelector('.badge-ok')).toBeNull();
		expect(of('hba matches').querySelector('.badge-ok')).not.toBeNull();
		expect(of('desired state unavailable').querySelector('.badge-ok')).toBeNull();
		expect(of('desired state unavailable').querySelector('.badge-unknown')).not.toBeNull();
		unmount(app);
	});

	it('shows the live checks, sync state and pools the edge reported', async () => {
		api({
			[EDGE]: [json(200, edge({ dirty: true, hba: { verdict: 'hba HAND-EDITED', state: 'bad' },
				pools: { headers: ['database', 'cl_active'], rows: [['alice_db', '3']] } }))]
		});
		const s = server({ health: { all_ok: false, edge: { ok: false, error: 'refused' }, postgres: { ok: true, error: null },
			drift: { ok: false, error: 'hba stale' }, checked_at: '2026-10-07T09:00:00Z', checked_ago: '2m' } });
		const { app, target } = await openEdge(s);
		const h = text(target, '#edge-health');
		expect(h).toContain('Edge listener: refused');
		expect(h).toContain('2m ago');
		expect(h).toContain('Rendered files: hba stale');
		expect(h).toContain('Dirty: the last sync failed or is pending');
		expect(h).toContain('hba HAND-EDITED');
		expect(target.querySelector('#bouncer-pools td')!.textContent).toBe('alice_db');
		unmount(app);
	});

	it('says when the bouncer console could not be read, apart from no pools', async () => {
		api({ [EDGE]: [json(200, edge({ pools: null }))] });
		const a = await openEdge();
		expect(a.target.querySelector('#pools-unavailable')?.classList.contains('empty-blind')).toBe(true);
		unmount(a.app);
		api({ [EDGE]: [json(200, edge({ pools: { headers: ['database'], rows: [] } }))] });
		const b = await openEdge();
		expect(b.target.querySelector('#pools-none')).not.toBeNull();
		expect(b.target.querySelector('#pools-unavailable')).toBeNull();
		unmount(b.app);
	});

	it('syncs the edge, and hands back the rendered files when there is no conf dir', async () => {
		const SYNC = 'POST /api/v1/admin/servers/s1/sync';
		const calls = api({
			[EDGE]: [json(200, edge()), json(200, edge()), json(200, edge())],
			[SYNC]: [
				json(200, { edge: { state: 'manual', rules: null, hba: 'host alice_db alice_db 10.0.0.0/24 scram-sha-256', knobs: '[databases]', error: null } }),
				json(200, { edge: { state: 'failed', rules: null, hba: null, knobs: null, error: 'RELOAD refused' } })
			]
		});
		const { app, target, onchanged } = await openEdge();
		button(target, 'Sync edge now')!.click();
		await settle();
		expect(calls.filter((c) => c === SYNC)).toHaveLength(1);
		expect(target.querySelector('#manual-hba')!.textContent).toContain('alice_db');
		expect(target.querySelector('#manual-knobs')!.textContent).toBe('[databases]');
		expect(document.activeElement).toBe(target.querySelector('[role=status]'));
		expect(onchanged).toHaveBeenCalledTimes(1);
		expect(calls.filter((c) => c === EDGE)).toHaveLength(2);
		button(target, 'Sync edge now')!.click();
		await settle();
		expect(target.querySelector('#manual-hba')).toBeNull();
		expect([...target.querySelectorAll('[role=alert]')].map((e) => e.textContent).join()).toContain('RELOAD refused');
		expect(document.activeElement).toBe(target.querySelector('[role=alert]'));
		unmount(app);
	});

	it('keeps the edge answer asked for after a sync over a slower one asked for before', async () => {
		let release!: (r: Response) => void;
		const slow = new Promise<Response>((r) => (release = r));
		let edges = 0;
		vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
			const key = `${init?.method ?? 'GET'} ${url}`;
			if (key === EDGE) return ++edges === 1 ? slow : json(200, edge({ dirty: false, hba: { verdict: 'fresh after sync', state: 'ok' } }));
			if (key === 'POST /api/v1/admin/servers/s1/sync') return json(200, { edge: { state: 'applied', rules: 1, hba: null, knobs: null, error: null } });
			throw new Error(`unexpected ${key}`);
		}));
		const { app, target } = await openEdge();
		button(target, 'Sync edge now')!.click();
		await settle();
		expect(target.querySelector('#edge-health')!.textContent).toContain('fresh after sync');
		release(json(200, edge({ dirty: true, hba: { verdict: 'stale from before', state: 'bad' } })));
		await settle();
		expect(target.querySelector('#edge-health')!.textContent).toContain('fresh after sync');
		expect(target.querySelector('#edge-health')!.textContent).not.toContain('stale from before');
		unmount(app);
	});
});

describe('AdminServers', () => {
	it('words health from the last sweep, and no sweep as no data', () => {
		const target = document.createElement('div');
		document.body.append(target);
		const h = (all_ok: boolean) => ({ all_ok, edge: { ok: all_ok, error: null }, postgres: { ok: true, error: null }, drift: null, checked_at: '', checked_ago: '1m' });
		const app = mount(AdminServers, {
			target,
			props: {
				servers: [server({ id: 'a', name: 'a' }), server({ id: 'b', name: 'b', health: h(true) }),
					server({ id: 'c', name: 'c', health: h(false), status: 'unreachable' })],
				serverHref: (id: string) => `/admin/servers/${id}`, settingsHref: (id: string) => `/admin/servers/${id}/settings`, addHref: '/admin/servers/new'
			}
		});
		flushSync();
		const rows = [...target.querySelectorAll('#servers tbody tr')].map((r) => r.textContent!.replace(/\s+/g, ' '));
		expect(rows[0]).toContain('No data yet');
		expect(rows[0]).not.toContain('Healthy');
		expect(rows[1]).toContain('Healthy');
		expect(rows[2]).toContain('Attention');
		expect(rows[2]).toContain('Unreachable');
		expect(target.querySelector('#servers a')!.getAttribute('href')).toBe('/admin/servers/a');
		unmount(app);
	});
});
