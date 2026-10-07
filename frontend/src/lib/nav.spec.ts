import { describe, expect, it } from 'vitest';
import { navFor, type Nav, type NavInput } from './nav.js';

const db = { name: 'eddy', status: 'active', server_name: 'local', engine: 'postgres', is_owner: true };
const server = { id: 's1', name: 'local', status: 'active', host: 'localhost', port: 5432, engine: 'postgres' };

// The path is documentation: navFor reads the route id, not the URL.
const at = (routeId: string, _path: string, over: Partial<NavInput> = {}): Nav =>
	navFor({ routeId, isAdmin: false, ...over });

const current = (nav: Nav) => nav.groups.flatMap((g) => g.items).filter((i) => i.current);
const labels = (nav: Nav) => nav.groups.flatMap((g) => g.items.map((i) => i.label));

describe('the workspace sidebar', () => {
	it('marks Databases on the dashboard, and only it', () => {
		const nav = at('/(app)/dashboard', '/dashboard');
		expect(nav.scope).toBeNull();
		expect(current(nav).map((i) => i.label)).toEqual(['Databases']);
		expect(current(nav)[0].href).toBe('/dashboard');
	});

	it('marks Provision on the provision page', () => {
		expect(current(at('/(app)/provision', '/provision')).map((i) => i.label)).toEqual(['Provision']);
	});

	it('shows the admin group to an admin and not to anyone else', () => {
		// The admin's view proves the group exists, so its absence below is a decision.
		const admin = at('/(app)/dashboard', '/dashboard', { isAdmin: true });
		expect(admin.groups.map((g) => g.label)).toContain('Admin');
		expect(labels(admin)).toContain('Users');

		const user = at('/(app)/dashboard', '/dashboard');
		expect(user.groups.map((g) => g.label)).not.toContain('Admin');
		expect(labels(user)).not.toContain('Users');
	});

	it('keeps a deeper admin page under its section', () => {
		const a = { isAdmin: true };
		expect(current(at('/(app)/admin', '/admin', a)).map((i) => i.label)).toEqual(['Overview']);
		expect(current(at('/(app)/admin/users/[id]', '/admin/users/u1', a)).map((i) => i.label)).toEqual(['Users']);
		expect(current(at('/(app)/admin/users/new', '/admin/users/new', a)).map((i) => i.label)).toEqual(['Users']);
		expect(current(at('/(app)/admin/databases', '/admin/databases', a)).map((i) => i.label)).toEqual(['All databases']);
	});

	it('treats adding a server as the servers list, not a server scope', () => {
		// Even with a server in the page data (a stale one, say), /new is not inside it.
		const nav = at('/(app)/admin/servers/new', '/admin/servers/new', { isAdmin: true, server });
		expect(at('/(app)/admin/servers/[id]', '/admin/servers/s1', { isAdmin: true, server }).scope?.kind).toBe('server');
		expect(nav.scope).toBeNull();
		expect(current(nav).map((i) => [i.label, i.current])).toEqual([['Servers', 'true']]);
	});

	it("calls a section's own page the page, and a page inside it only the section", () => {
		const a = { isAdmin: true };
		expect(current(at('/(app)/admin/users', '/admin/users', a)).map((i) => i.current)).toEqual(['page']);
		expect(current(at('/(app)/admin/users/[id]', '/admin/users/u1', a)).map((i) => i.current)).toEqual(['true']);
		expect(current(at('/(app)/dashboard', '/dashboard')).map((i) => i.current)).toEqual(['page']);
	});

	it('marks nothing on the profile, which lives in the footer', () => {
		const nav = at('/(app)/profile', '/profile', { isAdmin: true });
		// Premise: the same nav marks something elsewhere.
		expect(current(at('/(app)/dashboard', '/dashboard', { isAdmin: true }))).toHaveLength(1);
		expect(current(nav)).toEqual([]);
		expect(nav.profileCurrent).toBe(true);
	});
});

describe('the database sidebar', () => {
	it('lists the five sections, each its own page, the one you are on current', () => {
		const nav = at('/(app)/db/[name]/access', '/db/eddy/access', { db });
		expect(nav.scope).toMatchObject({ kind: 'database', name: 'eddy', status: 'active', meta: 'local · postgres' });
		expect(labels(nav)).toEqual(['Connect', 'Contents', 'Access', 'Backups', 'Manage']);
		expect(nav.groups[0].items.map((i) => i.href)).toEqual([
			'/db/eddy/connect', '/db/eddy/contents', '/db/eddy/access', '/db/eddy/backups', '/db/eddy/manage'
		]);
		expect(current(nav).map((i) => [i.label, i.current])).toEqual([['Access', 'page']]);
		expect(nav.here).toBe('Access');
	});

	it('marks every section on its own page', () => {
		for (const [key, label] of [['connect', 'Connect'], ['contents', 'Contents'], ['backups', 'Backups'], ['manage', 'Manage']]) {
			expect(current(at(`/(app)/db/[name]/${key}`, `/db/eddy/${key}`, { db })).map((i) => i.label)).toEqual([label]);
		}
	});

	it('keeps Backups current on a restore job page', () => {
		const nav = at('/(app)/db/[name]/restores/[id]', '/db/eddy/restores/r1', { db });
		expect(nav.scope?.name).toBe('eddy');
		// The section, not the page: Backups links to /db/eddy/backups, not here.
		expect(current(nav).map((i) => [i.label, i.current])).toEqual([['Backups', 'true']]);
	});

	it('leads an owner back to their databases and an admin to all of them', () => {
		expect(at('/(app)/db/[name]/connect', '/db/eddy/connect', { db }).scope?.back).toEqual({ label: 'Your databases', href: '/dashboard' });
		const theirs = at('/(app)/db/[name]/connect', '/db/eddy/connect', { db: { ...db, is_owner: false }, isAdmin: true });
		expect(theirs.scope?.back).toEqual({ label: 'All databases', href: '/admin/databases' });
	});

	it('falls back to the workspace when the database did not load', () => {
		// Premise: with the database loaded, this route is a database scope.
		expect(at('/(app)/db/[name]/manage', '/db/eddy/manage', { db }).scope?.kind).toBe('database');
		const nav = at('/(app)/db/[name]/manage', '/db/eddy/manage');
		expect(nav.scope).toBeNull();
		// Still somewhere: the databases you were looking among.
		expect(current(nav).map((i) => i.label)).toEqual(['Databases']);
	});
});

describe('the server sidebar', () => {
	it('groups its eight sections, each its own page, the one you are on current', () => {
		const nav = at('/(app)/admin/servers/[id]/overview', '/admin/servers/s1/overview', { isAdmin: true, server });
		expect(nav.scope).toMatchObject({
			kind: 'server', name: 'local', status: 'active', meta: 'localhost:5432 · postgres',
			back: { label: 'All servers', href: '/admin/servers' }
		});
		expect(nav.groups.map((g) => [g.label, g.items.map((i) => i.label)])).toEqual([
			['Status', ['Overview', 'Maintenance', 'Edge health']],
			['Edge', ['Pools', 'Sources', 'Listeners']],
			['Server', ['Settings', 'Credentials']]
		]);
		expect(nav.groups.flatMap((g) => g.items.map((i) => i.href))).toEqual(
			['overview', 'maintenance', 'edge', 'pools', 'sources', 'listeners', 'settings', 'credentials'].map((k) => `/admin/servers/s1/${k}`)
		);
		expect(current(nav).map((i) => [i.label, i.current])).toEqual([['Overview', 'page']]);
	});

	it('marks every section on its own page', () => {
		const sections = [['maintenance', 'Maintenance'], ['edge', 'Edge health'], ['pools', 'Pools'], ['sources', 'Sources'],
			['listeners', 'Listeners'], ['settings', 'Settings'], ['credentials', 'Credentials']];
		for (const [key, label] of sections) {
			const nav = at(`/(app)/admin/servers/[id]/${key}`, `/admin/servers/s1/${key}`, { isAdmin: true, server });
			expect(current(nav).map((i) => i.label), key).toEqual([label]);
			expect(nav.here).toBe(label);
		}
	});

	it('marks nothing on the bare server address, which only redirects', () => {
		const nav = at('/(app)/admin/servers/[id]', '/admin/servers/s1', { isAdmin: true, server });
		expect(nav.scope?.kind).toBe('server');
		expect(current(nav)).toEqual([]);
	});
});
