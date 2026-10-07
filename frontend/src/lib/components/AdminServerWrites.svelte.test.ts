import { flushSync, mount, unmount, type Component } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import AdminNewServer from './AdminNewServer.svelte';
import AdminServerCredentials from './AdminServerCredentials.svelte';
import AdminServerInit, { type InitReport } from './AdminServerInit.svelte';

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const fail = (status: number, code: string, message: string) => json(status, { error: { code, message } });

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
function type(t: ParentNode, name: string, value: string) {
	const el = t.querySelector(`[name=${name}]`) as HTMLInputElement | HTMLSelectElement;
	el.value = value;
	el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input', { bubbles: true }));
}
const field = (t: ParentNode, name: string) => (t.querySelector(`[name=${name}]`) as HTMLInputElement).value;
const submit = (t: ParentNode) => (t.querySelector('form') as HTMLFormElement).requestSubmit();
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mountIn<P extends Record<string, any>>(C: Component<P>, props: P) {
	const target = document.createElement('div');
	document.body.append(target);
	const app = mount(C, { target, props });
	flushSync();
	return { app, target };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllGlobals();
	document.body.innerHTML = '';
});

describe('AdminNewServer', () => {
	function fill(t: ParentNode) {
		type(t, 'name', 'pg-two');
		type(t, 'admin_dsn', 'postgres://cryptarch_admin:s3cret@db:5432/postgres');
		type(t, 'host', 'edge.lan');
		type(t, 'port', '6432');
		type(t, 'pool_mode', 'transaction');
	}

	it('sends what was typed, and forgets the DSNs once the server is added', async () => {
		api({ 'POST /api/v1/admin/servers': [json(201, { id: 'n1' })] });
		const onadded = vi.fn();
		const { app, target } = mountIn(AdminNewServer, { serversHref: '/admin/servers', onadded });
		fill(target);
		submit(target);
		await settle();
		expect(sent).toEqual([{ key: 'POST /api/v1/admin/servers', body: {
			name: 'pg-two', admin_dsn: 'postgres://cryptarch_admin:s3cret@db:5432/postgres', bouncer_dsn: null,
			host: 'edge.lan', port: 6432, pool_mode: 'transaction', tls_mode: 'off', backend_kind: 'docker', default_consumer_cidr: null
		} }]);
		expect(onadded).toHaveBeenCalledWith('n1');
		expect(field(target, 'admin_dsn')).toBe('');
		unmount(app);
	});

	it('keeps the form after a refusal so it can be corrected, until the page is hidden', async () => {
		api({ 'POST /api/v1/admin/servers': [fail(422, 'role_refused', "Refused: role 'postgres' is SUPERUSER.")] });
		const onadded = vi.fn();
		const { app, target } = mountIn(AdminNewServer, { serversHref: '/admin/servers', onadded });
		fill(target);
		submit(target);
		await settle();
		expect(target.querySelector('[role=alert]')!.textContent).toContain('SUPERUSER');
		expect(document.activeElement).toBe(target.querySelector('[role=alert]'));
		expect(onadded).not.toHaveBeenCalled();
		expect(field(target, 'admin_dsn')).toContain('s3cret');
		window.dispatchEvent(new Event('pagehide'));
		flushSync();
		expect(field(target, 'admin_dsn')).toBe('');
		expect(field(target, 'name')).toBe('pg-two');
		unmount(app);
	});
});

describe('AdminServerInit', () => {
	const report = (over: Partial<InitReport> = {}): InitReport => ({
		status: 'ready',
		steps: [{ step: 'Admin connection', ok: true, detail: 'connected' }, { step: 'Bouncer RELOAD', ok: false, detail: 'refused' }],
		bootstrap_sql: null, userlist_line: null, ...over
	});

	it('shows each step, and the bootstrap SQL only when it is needed', () => {
		const ondone = vi.fn();
		const a = mountIn(AdminServerInit, { report: report(), ondone });
		const rows = [...a.target.querySelectorAll('#init-steps tr')];
		expect(rows[0].querySelector('.badge-ok')!.textContent).toBe('connected');
		expect(rows[1].querySelector('.badge-danger')!.textContent).toBe('refused');
		expect(rows[1].querySelector('.badge-ok')).toBeNull();
		expect(a.target.querySelector('#bootstrap-sql')).toBeNull();
		unmount(a.app);
		const b = mountIn(AdminServerInit, { report: report({ status: 'needs_bootstrap', bootstrap_sql: 'GRANT SELECT ON pg_shadow TO "x";' }), ondone });
		expect(b.target.querySelector('#bootstrap-sql')!.textContent).toBe('GRANT SELECT ON pg_shadow TO "x";');
		unmount(b.app);
	});

	it('hands the userlist line over once: Done or leaving the page drops it', () => {
		const ondone = vi.fn();
		const { app, target } = mountIn(AdminServerInit, { report: report({ userlist_line: '"cryptarch_auth" "pw-abc"' }), ondone });
		expect(target.querySelector('#userlist-line')!.textContent).toBe('"cryptarch_auth" "pw-abc"');
		window.dispatchEvent(new Event('pagehide'));
		expect(ondone).toHaveBeenCalledTimes(1);
		[...target.querySelectorAll('button')].find((b) => b.textContent === 'Done')!.click();
		expect(ondone).toHaveBeenCalledTimes(2);
		unmount(app);
		window.dispatchEvent(new Event('pagehide'));
		expect(ondone).toHaveBeenCalledTimes(2);
	});
});

describe('AdminServerCredentials', () => {
	const PATH = 'POST /api/v1/admin/servers/s1/credentials';
	const open = () => {
		const onchanged = vi.fn(async () => {});
		return { ...mountIn(AdminServerCredentials, { serverId: 's1', hasAdminDsn: true, hasBouncerDsn: false, onchanged }), onchanged };
	};

	it('sends only what was typed, says what changed, and forgets it', async () => {
		api({ [PATH]: [json(200, { admin: false, bouncer: true, reconnected: null })] });
		const { app, target, onchanged } = open();
		expect(target.textContent).toContain('Stored (encrypted).');
		expect(target.textContent).toContain('Not set.');
		type(target, 'bouncer_dsn', '  postgres://pgb:pw@edge/pgbouncer ');
		submit(target);
		await settle();
		expect(sent[0].body).toEqual({ admin_dsn: null, bouncer_dsn: 'postgres://pgb:pw@edge/pgbouncer' });
		expect(target.querySelector('[role=status]')!.textContent).toBe('Bouncer console login replaced.');
		expect(field(target, 'bouncer_dsn')).toBe('');
		expect(onchanged).toHaveBeenCalledTimes(1);
		unmount(app);
	});

	it('claims a reconnect only when the server confirmed one', async () => {
		api({ [PATH]: [
			json(200, { admin: true, bouncer: false, reconnected: true }),
			json(200, { admin: true, bouncer: true, reconnected: false }),
			json(200, { admin: true, bouncer: false, reconnected: null })
		] });
		const { app, target } = open();
		const notices: string[] = [];
		for (let i = 0; i < 3; i++) {
			type(target, 'admin_dsn', 'postgres://new@db/postgres');
			submit(target);
			await settle();
			notices.push(target.querySelector('[role=status]')!.textContent!);
		}
		expect(notices[0]).toBe('Admin login replaced; Cryptarch reconnected with it.');
		expect(notices[1]).toContain('could not connect with it');
		expect(notices[1]).toContain('Bouncer console login replaced.');
		expect(notices[2]).toContain('The server is disabled');
		expect(notices.slice(1).join(' ')).not.toContain('reconnected with it');
		unmount(app);
	});

	it('shows a refusal and keeps the field, until the page is hidden', async () => {
		api({ [PATH]: [fail(422, 'role_refused', "Refused: role 'postgres' is SUPERUSER.")] });
		const { app, target, onchanged } = open();
		type(target, 'admin_dsn', 'postgres://postgres:pw@db/postgres');
		submit(target);
		await settle();
		expect(target.querySelector('[role=alert]')!.textContent).toContain('SUPERUSER');
		expect(target.querySelector('[role=status]')).toBeNull();
		expect(field(target, 'admin_dsn')).toContain('pw@db');
		expect(onchanged).not.toHaveBeenCalled();
		window.dispatchEvent(new Event('pagehide'));
		flushSync();
		expect(field(target, 'admin_dsn')).toBe('');
		unmount(app);
	});
});
