import { isHttpError } from '@sveltejs/kit';
import { describe, expect, it } from 'vitest';
import { load } from './+layout.js';

const run = (is_admin: boolean) =>
	(load as unknown as (e: { parent: () => Promise<unknown> }) => Promise<unknown>)({
		parent: async () => ({ me: { username: 'x', is_admin, must_change_password: false } })
	});

describe('(app)/admin layout load', () => {
	it('refuses a non-admin as a page, once', async () => {
		const err = await run(false).catch((e: unknown) => e);
		expect(isHttpError(err, 403)).toBe(true);
	});
	it('lets an admin through', async () => {
		expect(await run(true)).toEqual({});
	});
});
