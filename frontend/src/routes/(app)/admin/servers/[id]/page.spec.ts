import { isRedirect } from '@sveltejs/kit';
import { describe, expect, it } from 'vitest';
import { load } from './+page.js';

describe('a server address without a section', () => {
	it('goes to its Overview', () => {
		let location: string | null = null;
		try {
			(load as unknown as (e: { params: { id: string } }) => unknown)({ params: { id: 's1' } });
		} catch (e) {
			if (isRedirect(e)) location = e.location;
			else throw e;
		}
		expect(location).toBe('/admin/servers/s1/overview');
	});
});
