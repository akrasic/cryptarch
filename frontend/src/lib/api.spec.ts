import { describe, expect, it } from 'vitest';
import { api, ApiError } from './api';

/** A fetch double that records the request and answers with `response`. */
function recorder(response: Response) {
	const calls: { url: string; init: RequestInit }[] = [];
	const fetch = (async (url: string, init: RequestInit) => {
		calls.push({ url, init });
		return response;
	}) as unknown as typeof globalThis.fetch;
	return { calls, fetch };
}

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

describe('api', () => {
	it('sends a mutation as JSON even when it has nothing to say', async () => {
		// The server refuses any non-JSON mutation (its second CSRF lock), so an
		// empty DELETE must still carry the content type and a body.
		const { calls, fetch } = recorder(new Response(null, { status: 204 }));
		await api('DELETE', '/session', undefined, { fetch });
		const headers = calls[0].init.headers as Record<string, string>;
		expect(calls[0].url).toBe('/api/v1/session');
		expect(headers['Content-Type']).toBe('application/json');
		expect(calls[0].init.body).toBe('{}');
	});

	it('sends reads without a body and with same-origin credentials', async () => {
		const { calls, fetch } = recorder(json(200, { username: 'alice', is_admin: false }));
		const me = await api<{ username: string }>('GET', '/session', undefined, { fetch });
		expect(me.username).toBe('alice');
		expect(calls[0].init.body).toBeUndefined();
		expect(calls[0].init.credentials).toBe('same-origin');
	});

	it("turns the server's error body into a typed ApiError", async () => {
		const { fetch } = recorder(
			json(429, { error: { code: 'throttled', message: 'Too many failed attempts.' } })
		);
		const err = await api('POST', '/session', { username: 'a', password: 'b' }, { fetch }).catch(
			(e: unknown) => e
		);
		expect(err).toBeInstanceOf(ApiError);
		expect((err as ApiError).status).toBe(429);
		expect((err as ApiError).code).toBe('throttled');
		expect((err as ApiError).message).toBe('Too many failed attempts.');
	});

	it('still fails cleanly when an error response is not JSON', async () => {
		const { fetch } = recorder(new Response('<html>gateway</html>', { status: 502 }));
		const err = (await api('GET', '/session', undefined, { fetch }).catch((e) => e)) as ApiError;
		expect(err.status).toBe(502);
		expect(err.code).toBe('http_502');
	});

	it('reports a network failure as status 0, not as a server answer', async () => {
		const fetch = (async () => {
			throw new TypeError('Failed to fetch');
		}) as unknown as typeof globalThis.fetch;
		const err = (await api('GET', '/session', undefined, { fetch }).catch((e) => e)) as ApiError;
		expect(err.status).toBe(0);
		expect(err.code).toBe('network');
	});
});
