import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { Server } from '#lib/admin-servers.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		return await api<{ servers: Server[] }>('GET', '/admin/servers', undefined, { fetch });
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
};
