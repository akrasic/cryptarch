import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { PageLoad } from './$types';

export interface Overview {
	users: number;
	databases: number;
	servers: number;
	backups_enabled: boolean;
}

export const load: PageLoad = async ({ fetch }) => {
	try {
		return { overview: await api<Overview>('GET', '/admin/overview', undefined, { fetch }) };
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
};
