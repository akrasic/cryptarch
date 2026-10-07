import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { FleetDb } from '#lib/components/AdminDatabases.svelte';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		return { databases: (await api<{ databases: FleetDb[] }>('GET', '/admin/databases', undefined, { fetch })).databases };
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
};
