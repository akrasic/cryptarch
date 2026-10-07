import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { RestoreJob } from '#lib/components/RestoreJob.svelte';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, params }) => {
	try {
		return {
			name: params.name,
			job: await api<RestoreJob>(
				'GET',
				`/databases/${encodeURIComponent(params.name)}/restores/${encodeURIComponent(params.id)}`,
				undefined,
				{ fetch }
			)
		};
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
};
