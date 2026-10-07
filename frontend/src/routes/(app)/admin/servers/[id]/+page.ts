// A server's address alone goes to its Overview: each section is its own page
// (CRYPTARCH-155).
import { redirect } from '@sveltejs/kit';
import { resolve } from '$app/paths';
import type { PageLoad } from './$types';

export const load: PageLoad = ({ params }) => {
	redirect(307, resolve('/(app)/admin/servers/[id]/overview', { id: params.id }));
};
