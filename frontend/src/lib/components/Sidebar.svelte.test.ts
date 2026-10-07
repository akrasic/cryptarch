import { flushSync, mount, unmount, type ComponentProps } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { navFor } from '#lib/nav.js';
import Sidebar from './Sidebar.svelte';

const me = (is_admin = false) => ({ username: 'alice', is_admin, must_change_password: false });
const db = { name: 'eddy', status: 'active', server_name: 'local', engine: 'postgres', is_owner: true };

let target: HTMLElement;
let app: ReturnType<typeof mount> | null = null;

function render(props: ComponentProps<typeof Sidebar>) {
	target = document.createElement('div');
	document.body.append(target);
	app = mount(Sidebar, { target, props });
	flushSync();
}

afterEach(() => {
	if (app) unmount(app);
	app = null;
	target.remove();
});

const items = () => [...target.querySelectorAll<HTMLAnchorElement>('a.side-item')];

describe('Sidebar', () => {
	it('marks exactly the current item, for assistive tech as well as the eye', () => {
		const nav = navFor({ routeId: '/(app)/db/[name]/access', isAdmin: false, db });
		render({ nav, me: me(), signOutError: null, onsignout: () => {} });
		expect(items().map((a) => a.textContent)).toEqual(['Connect', 'Contents', 'Access', 'Backups', 'Manage']);
		expect(items().filter((a) => a.getAttribute('aria-current') === 'page').map((a) => a.textContent)).toEqual(['Access']);
		expect(target.querySelector('nav')?.getAttribute('aria-label')).toBe('Database eddy');
	});

	it('shows the database it is inside, with its status and a way back', () => {
		render({ nav: navFor({ routeId: '/(app)/db/[name]/connect', isAdmin: false, db }), me: me(), signOutError: null, onsignout: () => {} });
		expect(target.querySelector('.side-scope-name')?.textContent).toContain('eddy');
		expect(target.querySelector('.side-scope .badge')?.textContent).toBe('Active');
		expect(target.querySelector('.side-scope-meta')?.textContent).toBe('local · postgres');
		const back = target.querySelector<HTMLAnchorElement>('a.side-back');
		expect(back?.textContent).toBe('← Your databases');
		expect(back?.getAttribute('href')).toBe('/dashboard');
	});

	it('has no scope card in the workspace', () => {
		render({ nav: navFor({ routeId: '/(app)/dashboard', isAdmin: false }), me: me(), signOutError: null, onsignout: () => {} });
		// Premise: the workspace nav rendered at all.
		expect(items().map((a) => a.textContent)).toContain('Databases');
		expect(target.querySelector('.side-scope')).toBeNull();
		expect(target.querySelector('a.side-back')).toBeNull();
	});

	it('names the account, marks an admin, and signs out through the callback', () => {
		const onsignout = vi.fn();
		render({ nav: navFor({ routeId: '/(app)/profile', isAdmin: true }), me: me(true), signOutError: null, onsignout });
		const account = target.querySelector<HTMLAnchorElement>('a.side-account');
		expect(account?.querySelector('.side-user')?.textContent).toBe('alice');
		expect(account?.querySelector('.side-role')?.textContent).toBe('Administrator');
		expect(account?.getAttribute('aria-current')).toBe('page');
		target.querySelector<HTMLButtonElement>('button.side-signout')?.click();
		expect(onsignout).toHaveBeenCalledOnce();
	});

	it('gives an ordinary account no role line', () => {
		// Premise: the same render for an admin has one.
		render({ nav: navFor({ routeId: '/(app)/dashboard', isAdmin: true }), me: me(true), signOutError: null, onsignout: () => {} });
		expect(target.querySelector('a.side-account .side-role')).not.toBeNull();
		unmount(app!);
		target.remove();
		render({ nav: navFor({ routeId: '/(app)/dashboard', isAdmin: false }), me: me(), signOutError: null, onsignout: () => {} });
		expect(target.querySelector('a.side-account .side-user')?.textContent).toBe('alice');
		expect(target.querySelector('a.side-account .side-role')).toBeNull();
	});

	it('tells a page inside a section from the section page itself', () => {
		render({ nav: navFor({ routeId: '/(app)/db/[name]/restores/[id]', isAdmin: false, db }), me: me(), signOutError: null, onsignout: () => {} });
		const backups = items().find((a) => a.textContent === 'Backups');
		expect(backups?.getAttribute('aria-current')).toBe('true');
		expect(items().filter((a) => a.hasAttribute('aria-current'))).toHaveLength(1);
	});

	it('says when signing out failed', () => {
		render({ nav: navFor({ routeId: '/(app)/dashboard', isAdmin: false }), me: me(), signOutError: 'Sign-out failed — try again.', onsignout: () => {} });
		expect(target.querySelector('[role="alert"]')?.textContent).toBe('Sign-out failed — try again.');
	});
});
