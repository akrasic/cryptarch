// Every page about one server has it loaded once here, so the sidebar can show
// it whichever of its pages is open.
import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { Server } from '#lib/admin-servers.js';
import type { LayoutLoad } from './$types';

export const load: LayoutLoad = async ({ fetch, params, url }) => {
	// Read so SvelteKit reruns this on every move between the server's pages,
	// as each page's own load did before: Overview's health and status must
	// not come back stale from a visit to Settings.
	void url.pathname;
	try {
		return { server: await api<Server>('GET', `/admin/servers/${encodeURIComponent(params.id)}`, undefined, { fetch }) };
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
};
