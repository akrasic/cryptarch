import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import AdminBackups, { type Job, type LeftBehind, type Unreferenced } from './AdminBackups.svelte';

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const fail = (status: number, code: string, message: string) => json(status, { error: { code, message } });

const job = (id: string, status: string, over: Partial<Job> = {}): Job => ({
	id, db_name: `db_${id}`, metadata: false, created_at: '2026-10-07T09:30:00Z',
	size_bytes: status === 'running' ? null : 2048, took: '1.0s', status, error: null, log: '',
	verified: true, contents: { state: 'recorded', detail: null }, ...over
});
const jobs = (...list: Job[]) => ({ configured: true, running: list.some((j) => j.status === 'running'), jobs: list });
const leftBehind = (over: Partial<LeftBehind> = {}): LeftBehind => ({
	configured: true,
	backups: [
		{ id: 'g1', db_name: 'gone_db', created_at: '2026-10-01T08:00:00Z', status: 'ok', size_bytes: 2048, file_present: true },
		{ id: 'g2', db_name: 'lost_db', created_at: '2026-09-30T08:00:00Z', status: 'ok', size_bytes: 1024, file_present: false }
	],
	recorded_bytes: 3072,
	missing: 1,
	unchecked: 0,
	...over
});
const unref = (over: Partial<Unreferenced> = {}): Unreferenced => ({
	configured: true,
	files: [
		{ rel: 'x/20260101T000000Z-u1.dump.zst.enc', size_bytes: 12, recognised: true },
		{ rel: 'x/by-hand.dump', size_bytes: 4, recognised: false }
	],
	total_bytes: 16,
	...over
});

const JOBS = 'GET /api/v1/admin/backups';
const PURGE_G1 = 'POST /api/v1/admin/backups/g1/purge';
const PURGE_G2 = 'POST /api/v1/admin/backups/g2/purge';
const PURGE_FILE = 'POST /api/v1/admin/backups/purge-file';

let bodies: Record<string, unknown> = {};
function server(routes: Record<string, Response[]>) {
	const calls: string[] = [];
	bodies = {};
	vi.stubGlobal(
		'fetch',
		vi.fn(async (url: string, init?: RequestInit) => {
			const key = `${init?.method ?? 'GET'} ${url}`;
			calls.push(key);
			if (init?.body) bodies[key] = JSON.parse(init.body as string);
			const next = routes[key]?.shift();
			if (!next) throw new Error(`unexpected ${key}`);
			return next;
		})
	);
	return calls;
}

async function open(props: Partial<{ leftBehind: LeftBehind; unreferenced: Unreferenced | null; scanError: string | null }> = {}) {
	const target = document.createElement('div');
	document.body.append(target);
	const onchanged = vi.fn(async () => {});
	const app = mount(AdminBackups, {
		target,
		props: {
			leftBehind: leftBehind(),
			unreferenced: unref(),
			scanError: null,
			onchanged,
			dbHref: (name: string) => `/db/${name}`,
			...props
		}
	});
	await vi.advanceTimersByTimeAsync(0);
	flushSync();
	return { app, target, onchanged };
}
const button = (t: HTMLElement, text: string, label?: string) =>
	[...t.querySelectorAll('button')].find(
		(b) => b.textContent?.trim() === text && (!label || b.getAttribute('aria-label') === label)
	);
async function settle() {
	await vi.advanceTimersByTimeAsync(0);
	flushSync();
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllGlobals();
	document.body.innerHTML = '';
});

describe('AdminBackups', () => {
	it('follows the jobs list while one runs, and asks for nothing else (CRYPTARCH-124)', async () => {
		const calls = server({
			[JOBS]: [json(200, jobs(job('a', 'running'))), json(200, jobs(job('a', 'running'))), json(200, jobs(job('a', 'ok')))]
		});
		const { app, target } = await open();
		expect(target.querySelector('#backup-fleet')!.textContent).toContain('Running');
		await vi.advanceTimersByTimeAsync(3000);
		await vi.advanceTimersByTimeAsync(3000);
		flushSync();
		expect(calls).toEqual([JOBS, JOBS, JOBS]);
		expect(target.querySelector('#backup-fleet')!.textContent).toContain('Verified');
		await vi.advanceTimersByTimeAsync(30_000);
		expect(calls).toHaveLength(3);
		unmount(app);
	});

	it('links tenant databases, not Cryptarch\'s own, and counts failed and unverified jobs', async () => {
		server({
			[JOBS]: [json(200, jobs(
				job('m', 'ok', { db_name: '_cryptarch_meta', metadata: true }),
				job('t', 'ok', { verified: false }),
				job('f', 'failed', { error: 'pg_dump exited 1' })
			))]
		});
		const { app, target } = await open();
		const rows = [...target.querySelectorAll('#backup-fleet tbody tr')];
		expect(rows[0].querySelector('a')).toBeNull();
		expect(rows[0].textContent).toContain("Cryptarch's own");
		expect(rows[1].querySelector('a')!.getAttribute('href')).toBe('/db/db_t');
		expect(rows[1].textContent).toContain('Unverified');
		expect(rows[2].textContent).toContain('pg_dump exited 1');
		const counts = target.querySelector('#backup-counts')!.textContent!.replace(/\s+/g, ' ');
		expect(counts).toContain('1 failed.');
		expect(counts).toContain('1 succeeded but were never read back');
		unmount(app);
	});

	it('shows what was left behind, with the missing file and both totals', async () => {
		server({ [JOBS]: [json(200, jobs())] });
		const { app, target } = await open();
		const rows = [...target.querySelectorAll('#left-behind tbody tr')];
		expect(rows[0].textContent).toContain('gone_db');
		expect(rows[0].textContent).not.toContain('File missing');
		expect(rows[1].textContent).toContain('File missing');
		const totals = target.querySelector('#left-behind-totals')!.textContent!.replace(/\s+/g, ' ');
		expect(totals).toContain('2 backups, 3.0 kB recorded');
		expect(totals).toContain('1 has no file on disk');
		expect(target.textContent).toContain('No backups have run yet');
		unmount(app);
	});

	it('purges only after the confirm, and says when no file was found', async () => {
		const calls = server({
			[JOBS]: [json(200, jobs()), json(200, jobs()), json(200, jobs())],
			[PURGE_G1]: [json(200, { outcome: 'with_file' })],
			[PURGE_G2]: [json(200, { outcome: 'row_only' })]
		});
		const { app, target, onchanged } = await open();
		button(target, 'Purge', 'Purge the backup of gone_db taken 2026-10-01 08:00 UTC')!.click();
		flushSync();
		expect(document.querySelector('.dialog')!.textContent).toContain('Purge this backup of gone_db?');
		button(document.body, 'Cancel')!.click();
		flushSync();
		expect(document.querySelector('.dialog')).toBeNull();
		expect(calls).toEqual([JOBS]);

		button(target, 'Purge', 'Purge the backup of gone_db taken 2026-10-01 08:00 UTC')!.click();
		flushSync();
		document.querySelector<HTMLButtonElement>('.dialog button.btn-danger-solid')!.click();
		await settle();
		// The jobs list follows the purge; the disk lists are the page load's.
		expect(calls).toEqual([JOBS, PURGE_G1, JOBS]);
		expect(target.querySelector('[role=status]')!.textContent).toBe('Purged the backup of gone_db, and its file.');
		expect(onchanged).toHaveBeenCalledTimes(1);

		button(target, 'Purge', 'Purge the backup of lost_db taken 2026-09-30 08:00 UTC')!.click();
		flushSync();
		document.querySelector<HTMLButtonElement>('.dialog button.btn-danger-solid')!.click();
		await settle();
		expect(document.activeElement).toBe(target.querySelector('[role=status]'));
		expect(target.querySelector('[role=status]')!.textContent).toContain('no space was reclaimed');
		expect(onchanged).toHaveBeenCalledTimes(2);
		unmount(app);
	});

	it('reloads the lists when the purge finds them stale, and not when it failed', async () => {
		server({
			[JOBS]: [json(200, jobs())],
			[PURGE_G1]: [
				fail(500, 'purge_failed', 'The backup could not be purged and is still there.'),
				fail(404, 'no_such_backup', 'it may already be purged.')
			]
		});
		const { app, target, onchanged } = await open();
		for (const expected of ['still there', 'already be purged']) {
			button(target, 'Purge', 'Purge the backup of gone_db taken 2026-10-01 08:00 UTC')!.click();
			flushSync();
			document.querySelector<HTMLButtonElement>('.dialog button.btn-danger-solid')!.click();
			await settle();
			expect(target.querySelector('[role=alert]')!.textContent).toContain(expected);
			// The dialog is gone and the row's button was disabled meanwhile.
			expect(document.activeElement).toBe(target.querySelector('[role=alert]'));
			expect(target.querySelector('[role=status]')).toBeNull();
		}
		expect(onchanged).toHaveBeenCalledTimes(1);
		unmount(app);
	});

	it('deletes a recognised file by its path, and offers nothing for one it cannot identify', async () => {
		const calls = server({ [JOBS]: [json(200, jobs()), json(200, jobs())], [PURGE_FILE]: [json(200, { size_bytes: 12 })] });
		const { app, target, onchanged } = await open();
		const rows = [...target.querySelectorAll('#unreferenced tbody tr')];
		expect(rows[1].textContent).toContain('Unrecognised');
		expect(rows[1].querySelector('button')).toBeNull();
		expect(rows[0].querySelector('button')).not.toBeNull();
		expect(target.textContent!.replace(/\s+/g, ' ')).toContain('2 files, 16 B you would reclaim.');

		button(target, 'Delete', 'Delete x/20260101T000000Z-u1.dump.zst.enc')!.click();
		flushSync();
		expect(document.querySelector('.dialog')!.textContent).toContain('during a recovery');
		document.querySelector<HTMLButtonElement>('.dialog button.btn-danger-solid')!.click();
		await settle();
		expect(calls).toEqual([JOBS, PURGE_FILE, JOBS]);
		expect(bodies[PURGE_FILE]).toEqual({ rel: 'x/20260101T000000Z-u1.dump.zst.enc' });
		expect(target.querySelector('[role=status]')!.textContent).toBe('Deleted x/20260101T000000Z-u1.dump.zst.enc (12 B).');
		expect(onchanged).toHaveBeenCalledTimes(1);
		unmount(app);
	});

	it('never calls a file it could not look for missing', async () => {
		server({ [JOBS]: [json(200, jobs())] });
		const lb = leftBehind();
		lb.backups[1].file_present = null;
		const { app, target } = await open({ leftBehind: { ...lb, missing: 0, unchecked: 1 } });
		const rows = [...target.querySelectorAll('#left-behind tbody tr')];
		expect(rows[1].textContent).toContain('Not checked');
		expect(rows[1].textContent).not.toContain('File missing');
		const totals = target.querySelector('#left-behind-totals')!.textContent!.replace(/\s+/g, ' ');
		expect(totals).toContain('1 could not be checked');
		expect(totals).not.toContain('no file on disk');
		unmount(app);
	});

	it('says a scan that failed is unknown, never that the disk is clean', async () => {
		server({ [JOBS]: [json(200, jobs())] });
		const ok = await open({ unreferenced: unref({ files: [], total_bytes: 0 }) });
		expect(ok.target.textContent).toContain('Every file on the backup disk belongs');
		unmount(ok.app);
		document.body.innerHTML = '';
		server({ [JOBS]: [json(200, jobs())] });
		const bad = await open({ unreferenced: null, scanError: 'The backup disk could not be fully read.' });
		expect(bad.target.querySelector('#scan-failed')!.textContent).toContain('The backup disk could not be fully read.');
		expect(bad.target.querySelector('#scan-failed')!.classList.contains('empty-blind')).toBe(true);
		expect(bad.target.textContent).not.toContain('Every file on the backup disk belongs');
		unmount(bad.app);
	});

	it('says when backups are not configured', async () => {
		server({ [JOBS]: [json(200, { configured: false, running: false, jobs: [] })] });
		const { app, target } = await open({ leftBehind: leftBehind({ configured: false, backups: [] }) });
		expect(target.querySelector('#backups-off')!.textContent).toContain('Backups are off.');
		unmount(app);
	});
});
