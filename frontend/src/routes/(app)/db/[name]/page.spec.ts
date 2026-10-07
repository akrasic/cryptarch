import { isRedirect } from '@sveltejs/kit';
import { describe, expect, it } from 'vitest';
import { load } from './+page.js';

type Load = (e: { params: { name: string }; url: URL }) => unknown;
const go = (path: string) => {
	try {
		(load as unknown as Load)({ params: { name: 'eddy' }, url: new URL(`http://x${path}`) });
	} catch (e) {
		if (isRedirect(e)) return e.location;
		throw e;
	}
	return null;
};

describe('a database address without a section', () => {
	it('goes to Connect', () => {
		expect(go('/db/eddy')).toBe('/db/eddy/connect');
	});

	it('takes an old ?tab= link to that section', () => {
		expect(go('/db/eddy?tab=access')).toBe('/db/eddy/access');
		expect(go('/db/eddy?tab=backups')).toBe('/db/eddy/backups');
		expect(go('/db/eddy?tab=manage')).toBe('/db/eddy/manage');
	});

	it('takes an unknown ?tab= to Connect rather than nowhere', () => {
		expect(go('/db/eddy?tab=nope')).toBe('/db/eddy/connect');
	});
});
