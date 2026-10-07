import { api } from '#lib/api.js';
import type { ServerOption } from '#lib/provision.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => ({
	servers: (await api<{ servers: ServerOption[] }>('GET', '/servers', undefined, { fetch })).servers
});
