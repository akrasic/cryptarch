import { describe, expect, it, vi } from 'vitest';
import { load } from './+page.js';

function run(search: string) {
	const fetch = vi.fn(async (_url: string) =>
		new Response(JSON.stringify({ entries: [], older: 41 }), { status: 200, headers: { 'Content-Type': 'application/json' } })
	);
	const result = (load as unknown as (e: { fetch: unknown; url: URL }) => Promise<unknown>)({
		fetch,
		url: new URL(`http://x/admin/audit${search}`)
	});
	return { fetch, result };
}

describe('admin audit load', () => {
	it('asks for the newest page by default', async () => {
		const { fetch, result } = run('');
		expect(await result).toEqual({ entries: [], older: 41, paged: false });
		expect(fetch.mock.calls[0][0]).toBe('/api/v1/admin/audit');
	});
	it('passes the cursor through for an older page', async () => {
		const { fetch, result } = run('?before=42');
		expect(await result).toMatchObject({ paged: true });
		expect(fetch.mock.calls[0][0]).toBe('/api/v1/admin/audit?before=42');
	});
});
