// Every page in this group needs a signed-in user. The session is read once
// here; a 401 sends the browser to the login page.
import { error, redirect } from '@sveltejs/kit';
import { resolve } from '$app/paths';
import { api, ApiError, type Me } from '#lib/api.js';
import type { LayoutLoad } from './$types';

export const load: LayoutLoad = async ({ fetch, route }) => {
	try {
		const me = await api<Me>('GET', '/session', undefined, { fetch });
		// An admin-set password opens nothing but the page that replaces it
		// (CRYPTARCH-146). Every API call would answer 403
		// password_change_required anyway; this says why.
		if (me.must_change_password && route.id !== '/(app)/profile') {
			redirect(307, resolve('/(app)/profile'));
		}
		return { me };
	} catch (e) {
		if (e instanceof ApiError && e.status === 401) redirect(307, resolve('/login'));
		// Said in the server's words ("The metadata database is not answering"),
		// not swallowed as an unexpected "Internal Error".
		if (e instanceof ApiError) error(e.status, e.message);
		throw e;
	}
};
