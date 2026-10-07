// The admin area. The API refuses a non-admin on every call anyway (403);
// this says so once, as a page, instead of each page failing on its own.
import { error } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';

export const load: LayoutLoad = async ({ parent }) => {
	const { me } = await parent();
	if (!me.is_admin) error(403, "This needs admin rights, which your account doesn't have.");
	return {};
};
