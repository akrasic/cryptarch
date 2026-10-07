// Every page about one database (its sections, a restore job) has it loaded
// once here, so the sidebar can show it whichever page is open.
import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { LayoutLoad } from './$types';

export interface DatabaseView {
	name: string;
	status: string;
	server_name: string;
	engine: string;
	created_at: string;
	owner: string;
	is_owner: boolean;
	edge_dirty: boolean;
	connections: { label: string; conn: string }[];
	backups_enabled: boolean;
}

export const load: LayoutLoad = async ({ fetch, params, url }) => {
	// Read so SvelteKit reruns this on every move between pages under it
	// (a restore job → Manage), as the page's own load did before it moved
	// here: a status read on one page must not be shown stale on the next.
	// Every section is its own path, so each move between them is one small
	// GET, which keeps the sidebar's status current.
	void url.pathname;
	try {
		return {
			db: await api<DatabaseView>('GET', `/databases/${encodeURIComponent(params.name)}`, undefined, {
				fetch
			})
		};
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
};
