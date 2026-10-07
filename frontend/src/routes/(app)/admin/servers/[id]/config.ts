// The server's edge config (databases, named sources, listeners), for the
// pages that show a part of it: Pools, Sources and Listeners.
import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { Config } from '#lib/admin-servers.js';

export async function loadConfig(fetch: typeof globalThis.fetch, id: string): Promise<Config> {
	try {
		return await api<Config>('GET', `/admin/servers/${encodeURIComponent(id)}/config`, undefined, { fetch });
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
}
