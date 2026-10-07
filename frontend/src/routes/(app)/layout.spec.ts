import { isHttpError, isRedirect } from '@sveltejs/kit';
import { describe, expect, it } from 'vitest';
import { load } from './+layout.js';

const me = (must_change_password: boolean) =>
	(async () =>
		new Response(JSON.stringify({ username: 'alice', is_admin: false, must_change_password }), {
			status: 200,
			headers: { 'Content-Type': 'application/json' }
		})) as unknown as typeof fetch;

type Fetch = typeof globalThis.fetch;
// The load event is far wider than what this load reads; only `fetch` matters.
const run = (fetch: Fetch, routeId = '/(app)/dashboard') =>
	(load as unknown as (e: { fetch: Fetch; route: { id: string } }) => Promise<unknown>)({
		fetch,
		route: { id: routeId }
	});

describe('(app) layout load', () => {
	it('sends a session whose password an admin set to the profile, and nowhere else', async () => {
		const err = await run(me(true)).catch((e: unknown) => e);
		expect(isRedirect(err)).toBe(true);
		expect((err as { location: string }).location).toBe('/profile');
	});

	it('lets such a session onto the profile itself, or it could never get out', async () => {
		expect(await run(me(true), '/(app)/profile')).toEqual({
			me: { username: 'alice', is_admin: false, must_change_password: true }
		});
	});

	it('lets an ordinary session through', async () => {
		expect(await run(me(false))).toEqual({
			me: { username: 'alice', is_admin: false, must_change_password: false }
		});
	});

	it('says a failed session check in the server\'s words, and a signed-out one goes to sign-in', async () => {
		const answer = (status: number, message: string) =>
			(async () =>
				new Response(JSON.stringify({ error: { code: 'x', message } }), {
					status,
					headers: { 'Content-Type': 'application/json' }
				})) as unknown as typeof fetch;
		const down = await run(answer(503, 'The metadata database is not answering.')).catch((e: unknown) => e);
		expect(isHttpError(down) && [down.status, down.body.message]).toEqual([503, 'The metadata database is not answering.']);
		const out = await run(answer(401, 'Sign in.')).catch((e: unknown) => e);
		expect(isRedirect(out) && out.location).toBe('/login');
	});
});

