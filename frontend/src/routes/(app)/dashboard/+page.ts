import { api } from '#lib/api.js';
import type { PageLoad } from './$types';

export interface DatabaseRow {
	name: string;
	status: string;
	server_name: string;
}

export interface DatabaseList {
	databases: DatabaseRow[];
	/** False: the list could not be read, so an empty one means "unseen". */
	listed: boolean;
	/** known false: the quota could not be read; used and limit are not the account's. */
	quota: { used: number; limit: number | null; at_cap: boolean; known: boolean };
}

export const load: PageLoad = async ({ fetch }) => ({
	list: await api<DatabaseList>('GET', '/databases', undefined, { fetch })
});
