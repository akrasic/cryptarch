import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { AdminUser, UserDb } from '#lib/admin.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, params }) => {
	try {
		return {
			detail: await api<{ user: AdminUser; is_self: boolean; databases: UserDb[] }>(
				'GET',
				`/admin/users/${encodeURIComponent(params.id)}`,
				undefined,
				{ fetch }
			)
		};
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
};
