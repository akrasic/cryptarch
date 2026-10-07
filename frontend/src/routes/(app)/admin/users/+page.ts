import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { AdminUser } from '#lib/admin.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		return { users: (await api<{ users: AdminUser[] }>('GET', '/admin/users', undefined, { fetch })).users };
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
};
