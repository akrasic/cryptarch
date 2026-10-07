// A database's address alone, or an old ?tab= link (CRYPTARCH-96), goes to
// the section it names: each section is its own page now (CRYPTARCH-152).
import { redirect } from '@sveltejs/kit';
import { resolve } from '$app/paths';
import { sectionFrom } from '#lib/sections.js';
import type { PageLoad } from './$types';

const ROUTE = {
	connect: '/(app)/db/[name]/connect',
	contents: '/(app)/db/[name]/contents',
	access: '/(app)/db/[name]/access',
	backups: '/(app)/db/[name]/backups',
	manage: '/(app)/db/[name]/manage'
} as const;

export const load: PageLoad = ({ params, url }) => {
	redirect(307, resolve(ROUTE[sectionFrom(url.searchParams.get('tab'))], { name: params.name }));
};
