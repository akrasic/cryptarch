import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import BackupsTab from './BackupsTab.svelte';

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

const backup = (id: string, status: string, extra: Record<string, unknown> = {}) => ({
	id,
	created_at: '2026-10-07T09:30:00Z',
	finished_at: status === 'running' ? null : '2026-10-07T09:31:00Z',
	size_bytes: status === 'running' ? null : 2048,
	took: '1.0s',
	status,
	error: null,
	log: '',
	verified: false,
	contents: { state: 'unknown', detail: 'no manifest' },
	...extra
});
const list = (...backups: unknown[]) => ({ enabled: true, backups });

const LIST = 'GET /api/v1/databases/alice_db/backups';
const START = 'POST /api/v1/databases/alice_db/backups';
const RESTORES = 'GET /api/v1/databases/alice_db/restores';
const RESTORE = 'POST /api/v1/databases/alice_db/restores';

/** Answers from queues per "METHOD path". The restore history is asked for
 *  on every open; unless a test queues answers for it, it is empty and its
 *  calls are kept out of `calls` (see `restoreCalls`). */
let restoreCalls: { key: string; body: unknown }[] = [];

function server(routes: Record<string, Response[]>) {
	const calls: string[] = [];
	restoreCalls = [];
	vi.stubGlobal(
		'fetch',
		vi.fn(async (url: string, init?: RequestInit) => {
			const key = `${init?.method ?? 'GET'} ${url}`;
			const isRestore = key === RESTORES || key === RESTORE;
			if (isRestore) restoreCalls.push({ key, body: init?.body ? JSON.parse(init.body as string) : undefined });
			else calls.push(key);
			const next = routes[key]?.shift();
			if (!next && key === RESTORES) return json(200, { restores: [] });
			if (!next) throw new Error(`unexpected ${key}`);
			return next;
		})
	);
	return calls;
}

async function open(isOwner = true) {
	const target = document.createElement('div');
	document.body.append(target);
	const onrestore = vi.fn();
	const app = mount(BackupsTab, {
		target,
		props: { name: 'alice_db', isOwner, onrestore, jobHref: (id: string) => `/db/alice_db/restores/${id}` }
	});
	await vi.advanceTimersByTimeAsync(0);
	flushSync();
	return { app, target, onrestore };
}
const button = (t: HTMLElement, text: string) =>
	[...t.querySelectorAll('button')].find((b) => b.textContent?.trim() === text);

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllGlobals();
	document.body.innerHTML = '';
});

describe('BackupsTab', () => {
	it('follows a running backup until it settles, then stops asking', async () => {
		const calls = server({
			[LIST]: [
				json(200, list(backup('a', 'running'))),
				json(200, list(backup('a', 'running'))),
				json(200, list(backup('a', 'ok', { verified: true })))
			]
		});
		const { app, target } = await open();
		expect(target.textContent).toContain('Running');
		await vi.advanceTimersByTimeAsync(3000);
		await vi.advanceTimersByTimeAsync(3000);
		flushSync();
		expect(calls).toEqual([LIST, LIST, LIST]);
		expect(target.textContent).toContain('Verified');
		await vi.advanceTimersByTimeAsync(30_000);
		expect(calls).toHaveLength(3);
		unmount(app);
	});

	it('stops following when the tab goes away', async () => {
		const calls = server({ [LIST]: [json(200, list(backup('a', 'running')))] });
		const { app } = await open();
		unmount(app);
		await vi.advanceTimersByTimeAsync(30_000);
		expect(calls).toEqual([LIST]);
	});

	it('starts a backup and follows the one it started', async () => {
		const calls = server({
			[LIST]: [json(200, list()), json(200, list(backup('n', 'running'))), json(200, list(backup('n', 'ok')))],
			[START]: [json(202, { id: 'n' })]
		});
		const { app, target } = await open();
		expect(target.textContent).toContain('No backups yet');
		button(target, 'Back up now')!.click();
		await vi.advanceTimersByTimeAsync(0);
		flushSync();
		expect(target.querySelector('[role=status]')?.textContent).toBe('Backup started.');
		expect(target.textContent).toContain('Running');
		await vi.advanceTimersByTimeAsync(3000);
		flushSync();
		expect(calls).toEqual([LIST, START, LIST, LIST]);
		unmount(app);
	});

	it('stops asking once the answer cannot change', async () => {
		const calls = server({
			[LIST]: [
				json(200, list(backup('a', 'running'))),
				json(404, { error: { code: 'not_found', message: 'There is no database by that name.' } })
			]
		});
		const { app, target } = await open();
		await vi.advanceTimersByTimeAsync(3000);
		flushSync();
		expect(target.querySelector('[role=alert]')?.textContent).toBe('There is no database by that name.');
		await vi.advanceTimersByTimeAsync(30_000);
		expect(calls).toEqual([LIST, LIST]);
		unmount(app);
	});

	it('shows the running backup it was refused because of', async () => {
		const calls = server({
			[LIST]: [json(200, list()), json(200, list(backup('s', 'running'))), json(200, list(backup('s', 'ok')))],
			[START]: [json(409, { error: { code: 'already_running', message: 'Backup not started: a backup of this database is already running' } })]
		});
		const { app, target } = await open();
		button(target, 'Back up now')!.click();
		await vi.advanceTimersByTimeAsync(0);
		flushSync();
		expect(target.textContent).toContain('Running');
		expect(calls).toEqual([LIST, START, LIST]);
		unmount(app);
	});

	it('says why a backup did not start', async () => {
		server({
			[LIST]: [json(200, list())],
			[START]: [json(409, { error: { code: 'restore_running', message: 'Backup not started: a restore of this database is running' } })]
		});
		const { app, target } = await open();
		button(target, 'Back up now')!.click();
		await vi.advanceTimersByTimeAsync(0);
		flushSync();
		expect(target.querySelector('[role=alert]')?.textContent).toBe(
			'Backup not started: a restore of this database is running'
		);
		expect(target.querySelector('[role=status]')).toBeNull();
		unmount(app);
	});

	it('offers nothing to start to someone who does not own the database', async () => {
		server({ [LIST]: [json(200, list(backup('a', 'ok')))] });
		const { app, target } = await open(false);
		expect(button(target, 'Back up now')).toBeUndefined();
		expect(target.textContent).toContain('2.0 kB');
		unmount(app);
	});

	it('says so when backups are not configured', async () => {
		server({ [LIST]: [json(200, { enabled: false, backups: [] })] });
		const { app, target } = await open();
		expect(target.textContent).toContain('Backups are off on this deployment');
		expect(button(target, 'Back up now')).toBeUndefined();
		unmount(app);
	});

	it('restores only after the name is typed, and goes to the job it started', async () => {
		const calls = server({
			[LIST]: [json(200, list(backup('a', 'ok'), backup('r', 'running'), backup('f', 'failed')))],
			[RESTORE]: [json(202, { id: 'job1' })]
		});
		const { app, target, onrestore } = await open();
		const restoreButtons = [...target.querySelectorAll('button')].filter((b) => b.textContent === 'Restore');
		expect(restoreButtons).toHaveLength(1);
		restoreButtons[0].click();
		flushSync();
		const dialog = target.querySelector('.dialog')!;
		expect(dialog.textContent).toContain('if it succeeds, there is no undo');
		const field = dialog.querySelector<HTMLInputElement>('input[name=confirm]')!;
		// Sent as typed, so the server's check sees what the user typed.
		field.value = ' alice_db ';
		field.dispatchEvent(new Event('input'));
		flushSync();
		dialog.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
		await vi.advanceTimersByTimeAsync(0);
		expect(restoreCalls.filter((c) => c.key === RESTORE)).toEqual([
			{ key: RESTORE, body: { backup_id: 'a', confirm: ' alice_db ' } }
		]);
		expect(onrestore).toHaveBeenCalledExactlyOnceWith('job1');
		unmount(app);
	});

	it('says why a restore did not start', async () => {
		server({
			[LIST]: [json(200, list(backup('a', 'ok')))],
			[RESTORE]: [json(409, { error: { code: 'wrong_key', message: 'Restore not started: this backup was sealed with a different encryption key' } })]
		});
		const { app, target, onrestore } = await open();
		button(target, 'Restore')!.click();
		flushSync();
		const field = target.querySelector<HTMLInputElement>('input[name=confirm]')!;
		field.value = 'alice_db';
		field.dispatchEvent(new Event('input'));
		flushSync();
		target.querySelector('.dialog form')!.dispatchEvent(new Event('submit', { cancelable: true }));
		await vi.advanceTimersByTimeAsync(0);
		flushSync();
		expect(target.querySelector('[role=alert]')?.textContent).toContain('different encryption key');
		expect(onrestore).not.toHaveBeenCalled();
		unmount(app);
	});

	it('offers no restore to someone who does not own the database', async () => {
		server({ [LIST]: [json(200, list(backup('a', 'ok')))] });
		const { app, target } = await open(false);
		expect(target.textContent).toContain('2.0 kB'); // PRECONDITION: the backup rendered
		expect(button(target, 'Restore')).toBeUndefined();
		unmount(app);
	});

	it('stops following restores when the tab goes away', async () => {
		server({
			[LIST]: [json(200, list())],
			[RESTORES]: [json(200, { restores: [{ id: 'j', created_at: '2026-10-07T10:00:00Z', status: 'running', requested_by: 'alice', stage_title: null }] })]
		});
		const { app } = await open();
		expect(restoreCalls).toHaveLength(1);
		unmount(app);
		await vi.advanceTimersByTimeAsync(30_000);
		expect(restoreCalls).toHaveLength(1);
	});

	it('cannot start a second restore while one is being started', async () => {
		let release!: (r: Response) => void;
		server({ [LIST]: [json(200, list(backup('a', 'ok'), backup('b', 'ok')))] });
		const fetchMock = globalThis.fetch as ReturnType<typeof vi.fn>;
		const inner = fetchMock.getMockImplementation() as (url: string, init?: RequestInit) => Promise<Response>;
		fetchMock.mockImplementation((url: string, init?: RequestInit) =>
			init?.method === 'POST' ? new Promise<Response>((r) => (release = r)) : inner(url, init)
		);
		const { app, target } = await open();
		const restoreButtons = () => [...target.querySelectorAll('button')].filter((b) => b.textContent === 'Restore');
		restoreButtons()[0].click();
		flushSync();
		const field = target.querySelector<HTMLInputElement>('.dialog input[name=confirm]')!;
		field.value = 'alice_db';
		field.dispatchEvent(new Event('input'));
		flushSync();
		target.querySelector('.dialog form')!.dispatchEvent(new Event('submit', { cancelable: true }));
		flushSync();
		expect(restoreButtons().every((b) => b.disabled)).toBe(true);
		release(json(202, { id: 'j' }));
		await vi.advanceTimersByTimeAsync(0);
		unmount(app);
	});

	it('shows the restore history, following a running one', async () => {
		const restore = (status: string) => ({
			id: 'job1', created_at: '2026-10-07T10:00:00Z', status, requested_by: 'alice',
			stage_title: status === 'running' ? 'Load it in one transaction' : null
		});
		const calls = server({
			[LIST]: [json(200, list(backup('a', 'ok')))],
			[RESTORES]: [json(200, { restores: [restore('running')] }), json(200, { restores: [restore('ok')] })]
		});
		const { app, target } = await open();
		expect(target.textContent).toContain('Load it in one transaction…');
		expect(target.querySelector<HTMLAnchorElement>('#restore-history a')?.getAttribute('href')).toBe(
			'/db/alice_db/restores/job1'
		);
		await vi.advanceTimersByTimeAsync(2000);
		flushSync();
		expect(target.textContent).not.toContain('Load it in one transaction…');
		await vi.advanceTimersByTimeAsync(20_000);
		expect(restoreCalls).toHaveLength(2);
		unmount(app);
	});

	it('keeps the three contents states and the verified mark apart', async () => {
		server({
			[LIST]: [
				json(200, list(
					backup('u', 'ok', { contents: { state: 'unknown', detail: 'no manifest' } }),
					backup('c', 'ok', { verified: true, contents: { state: 'needs_care', detail: '1 SECURITY DEFINER function' } }),
					backup('r', 'ok', { verified: true, contents: { state: 'recorded', detail: null } }),
					backup('f', 'failed', { error: 'pg_dump exited 1', log: 'pg_dump: error: boom' })
				))
			]
		});
		const { app, target } = await open();
		// Lowercased: badges say their word in sentence case.
		const rows = [...target.querySelectorAll('tbody tr:not(.logrow)')].map((r) => (r.textContent ?? '').toLowerCase());
		expect(rows[0]).toContain('unverified');
		expect(rows[0]).toContain('unknown');
		expect(rows[1]).toContain('verified');
		expect(rows[1]).not.toContain('unverified');
		expect(rows[1]).toContain('needs care');
		expect(rows[2]).toContain('recorded');
		expect(rows[3]).toContain('pg_dump exited 1');
		expect(rows[3]).not.toContain('verified');
		expect(target.querySelector('pre.log')?.textContent).toBe('pg_dump: error: boom');
		unmount(app);
	});
});
