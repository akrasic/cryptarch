// The admin Backups page: the two lists that walk the backup disk, read once per
// visit (and again after a purge). The jobs list is the component's own, since
// it is the one that follows a running job.
import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { LeftBehind, Unreferenced } from '#lib/components/AdminBackups.svelte';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	const unreferenced = api<Unreferenced>('GET', '/admin/backups/unreferenced', undefined, { fetch }).then(
		(u) => ({ unreferenced: u, scanError: null }),
		// A scan that could not read the disk: said in its own section, while
		// the rest of the page still shows. Anything else fails the page.
		(e) => {
			if (e instanceof ApiError && e.code === 'scan_failed') return { unreferenced: null, scanError: e.message };
			throw e;
		}
	);
	try {
		const [leftBehind, scan] = await Promise.all([
			api<LeftBehind>('GET', '/admin/backups/left-behind', undefined, { fetch }),
			unreferenced
		]);
		return { leftBehind, ...scan };
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
};
