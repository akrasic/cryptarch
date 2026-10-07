// The root is the dashboard (the layout sends a signed-out visitor to the login).
import { redirect } from '@sveltejs/kit';
import { resolve } from '$app/paths';

export const load = () => redirect(307, resolve('/(app)/dashboard'));
