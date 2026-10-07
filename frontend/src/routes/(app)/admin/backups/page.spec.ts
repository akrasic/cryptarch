import { describe, expect, it, vi } from 'vitest';
import { load } from './+page.js';

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const LB = { configured: true, backups: [], recorded_bytes: 0, missing: 0 };

function run(unreferenced: Response) {
	const fetch = vi.fn(async (url: string) =>
		url.endsWith('/left-behind') ? json(200, LB) : unreferenced
	);
	return (load as unknown as (e: { fetch: unknown }) => Promise<unknown>)({ fetch });
}

describe('admin backups load', () => {
	it('reads both disk lists, and never the jobs list the page polls', async () => {
		const files = { configured: true, files: [], total_bytes: 0 };
		const fetch = vi.fn(async (url: string) => json(200, url.endsWith('/left-behind') ? LB : files));
		const r = await (load as unknown as (e: { fetch: unknown }) => Promise<unknown>)({ fetch });
		expect(r).toEqual({ leftBehind: LB, unreferenced: files, scanError: null });
		expect(fetch.mock.calls.map((c) => c[0]).sort()).toEqual([
			'/api/v1/admin/backups/left-behind',
			'/api/v1/admin/backups/unreferenced'
		]);
	});
	it('keeps the page when only the scan failed, and says so', async () => {
		const r = await run(json(500, { error: { code: 'scan_failed', message: 'could not be fully read' } }));
		expect(r).toEqual({ leftBehind: LB, unreferenced: null, scanError: 'could not be fully read' });
	});
	it('fails the page for any other error', async () => {
		await expect(run(json(500, { error: { code: 'internal', message: 'Something went wrong.' } }))).rejects.toMatchObject({
			status: 500
		});
	});
});
