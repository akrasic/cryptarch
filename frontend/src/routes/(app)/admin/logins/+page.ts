import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { Logins } from '#lib/components/AdminLogins.svelte';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		return { report: await api<Logins>('GET', '/admin/logins', undefined, { fetch }) };
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
};
