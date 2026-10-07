// The audit log: newest first, a page at a time; ?before= is the cursor
// the previous page named.
import { error } from '@sveltejs/kit';
import { api, ApiError } from '#lib/api.js';
import type { PageLoad } from './$types';

export interface AuditEntry {
	id: number;
	actor: string;
	action: string;
	target: string | null;
	detail: string | null;
	created_at: string;
}

export const load: PageLoad = async ({ fetch, url }) => {
	const before = url.searchParams.get('before');
	try {
		const page = await api<{ entries: AuditEntry[]; older: number | null }>(
			'GET',
			before ? `/admin/audit?before=${encodeURIComponent(before)}` : '/admin/audit',
			undefined,
			{ fetch }
		);
		return { ...page, paged: before !== null };
	} catch (e) {
		if (e instanceof ApiError && e.status !== 401) error(e.status, e.message);
		throw e;
	}
};
