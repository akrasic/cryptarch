// The sidebar's contents for a route. The sidebar follows where you are: the
// workspace, or the database or server you are inside, each with a way back
// out (CRYPTARCH-151, the Keyring layout). Pure, so every route's answer is
// a unit test rather than a screenshot.
import { resolve } from '$app/paths';
import { SECTIONS } from './sections.js';

/**
 * 'page' when the item IS the page you are on; 'true' when you are on a page
 * inside its section (a restore job under Backups, a user under Users), so a
 * screen reader does not call a link to another page the current one.
 */
export type Current = false | 'page' | 'true';

export interface NavItem {
	label: string;
	href: string;
	current: Current;
}

export interface NavGroup {
	label?: string;
	items: NavItem[];
}

export interface NavScope {
	kind: 'database' | 'server';
	name: string;
	status: string;
	meta: string;
	back: { label: string; href: string };
}

export interface Nav {
	scope: NavScope | null;
	groups: NavGroup[];
	/** The current item's label, for the phone's section switcher. */
	here: string | null;
	/** The profile page, which the footer's account link stands for. */
	profileCurrent: boolean;
}

export interface NavInput {
	routeId: string;
	isAdmin: boolean;
	/** The database this page is about, once its layout has loaded it. */
	db?: { name: string; status: string; server_name: string; engine: string; is_owner: boolean };
	/** The server this page is about, once its layout has loaded it. */
	server?: { id: string; name: string; status: string; host: string; port: number; engine: string };
}

const under = (routeId: string, prefix: string) => routeId === prefix || routeId.startsWith(`${prefix}/`);

/** 'page' on the route itself, 'true' below it, false elsewhere. */
const at = (routeId: string, prefix: string): Current =>
	routeId === prefix ? 'page' : under(routeId, prefix) ? 'true' : false;
/** Exactly one of `routes` makes this the current page. */
const on = (routeId: string, ...routes: string[]): Current => (routes.includes(routeId) ? 'page' : false);

function finish(scope: NavScope | null, groups: NavGroup[], routeId: string): Nav {
	const hit = groups.flatMap((g) => g.items).find((i) => i.current);
	return { scope, groups, here: hit?.label ?? null, profileCurrent: routeId === '/(app)/profile' };
}

// Literal route ids, so resolve() can check each one exists.
const SECTION_ROUTE = {
	connect: '/(app)/db/[name]/connect',
	contents: '/(app)/db/[name]/contents',
	access: '/(app)/db/[name]/access',
	backups: '/(app)/db/[name]/backups',
	manage: '/(app)/db/[name]/manage'
} as const;

function database(input: NavInput, db: NonNullable<NavInput['db']>): Nav {
	const r = input.routeId;
	const items = SECTIONS.map((s) => {
		const route = SECTION_ROUTE[s.key];
		// A restore job is a page inside Backups.
		const inside = s.key === 'backups' && under(r, '/(app)/db/[name]/restores');
		return {
			label: s.title,
			href: resolve(route, { name: db.name }),
			current: (r === route ? 'page' : inside ? 'true' : false) as Current
		};
	});
	const back = db.is_owner
		? { label: 'Your databases', href: resolve('/(app)/dashboard') }
		: { label: 'All databases', href: resolve('/(app)/admin/databases') };
	const scope: NavScope = { kind: 'database', name: db.name, status: db.status, meta: `${db.server_name} · ${db.engine}`, back };
	return finish(scope, [{ items }], r);
}

// A server's sections, grouped as the sidebar shows them, with literal route
// ids so resolve() can check each one exists.
const SERVER_GROUPS = [
	{
		label: 'Status',
		items: [
			['Overview', '/(app)/admin/servers/[id]/overview'],
			['Maintenance', '/(app)/admin/servers/[id]/maintenance'],
			['Edge health', '/(app)/admin/servers/[id]/edge']
		]
	},
	{
		label: 'Edge',
		items: [
			['Pools', '/(app)/admin/servers/[id]/pools'],
			['Sources', '/(app)/admin/servers/[id]/sources'],
			['Listeners', '/(app)/admin/servers/[id]/listeners']
		]
	},
	{
		label: 'Server',
		items: [
			['Settings', '/(app)/admin/servers/[id]/settings'],
			['Credentials', '/(app)/admin/servers/[id]/credentials']
		]
	}
] as const;

function server(input: NavInput, s: NonNullable<NavInput['server']>): Nav {
	const groups = SERVER_GROUPS.map((g) => ({
		label: g.label,
		items: g.items.map(([label, route]) => ({
			label,
			href: resolve(route, { id: s.id }),
			current: on(input.routeId, route)
		}))
	}));
	const scope: NavScope = {
		kind: 'server', name: s.name, status: s.status, meta: `${s.host}:${s.port} · ${s.engine}`,
		back: { label: 'All servers', href: resolve('/(app)/admin/servers') }
	};
	return finish(scope, groups, input.routeId);
}

function workspace(input: NavInput): Nav {
	const r = input.routeId;
	const groups: NavGroup[] = [
		{
			items: [
				{ label: 'Databases', href: resolve('/(app)/dashboard'), current: on(r, '/(app)/dashboard') || (under(r, '/(app)/db') ? 'true' : false) },
				{ label: 'Provision', href: resolve('/(app)/provision'), current: on(r, '/(app)/provision') }
			]
		}
	];
	if (input.isAdmin) {
		groups.push({
			label: 'Admin',
			items: [
				{ label: 'Overview', href: resolve('/(app)/admin'), current: on(r, '/(app)/admin') },
				{ label: 'Users', href: resolve('/(app)/admin/users'), current: at(r, '/(app)/admin/users') },
				{ label: 'Servers', href: resolve('/(app)/admin/servers'), current: at(r, '/(app)/admin/servers') },
				{ label: 'All databases', href: resolve('/(app)/admin/databases'), current: at(r, '/(app)/admin/databases') },
				{ label: 'Backups', href: resolve('/(app)/admin/backups'), current: at(r, '/(app)/admin/backups') },
				{ label: 'Audit log', href: resolve('/(app)/admin/audit'), current: at(r, '/(app)/admin/audit') },
				{ label: 'Login report', href: resolve('/(app)/admin/logins'), current: at(r, '/(app)/admin/logins') }
			]
		});
	}
	return finish(null, groups, r);
}

export function navFor(input: NavInput): Nav {
	const r = input.routeId;
	// A page whose object did not load (an error page) keeps the workspace:
	// a scope card with nothing in it would claim a place that is not there.
	if (under(r, '/(app)/db/[name]') && input.db) return database(input, input.db);
	if (under(r, '/(app)/admin/servers/[id]') && input.server) return server(input, input.server);
	return workspace(input);
}
