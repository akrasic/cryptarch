// The shapes of /api/v1/admin/servers (src/api/admin_servers.rs).

export interface Check {
	ok: boolean;
	error: string | null;
}

export interface Health {
	all_ok: boolean;
	edge: Check;
	postgres: Check;
	/** The rendered files against the desired state; null when not checkable. */
	drift: Check | null;
	checked_at: string;
	checked_ago: string;
}

export interface Server {
	id: string;
	name: string;
	engine: string;
	host: string;
	port: number;
	is_active: boolean;
	pool_mode: string;
	default_pool_size: number;
	max_client_conn: number;
	max_db_connections: number;
	max_user_connections: number;
	tls_mode: string;
	backend_kind: string;
	default_consumer_cidr: string | null;
	has_admin_dsn: boolean;
	has_bouncer_dsn: boolean;
	db_count: number;
	init_status: string;
	bouncer_conf_dir: string | null;
	edge_dirty: boolean;
	edge_synced_at: string | null;
	/** "disabled", "active", or "unreachable": enabled, but no engine. */
	status: string;
	/** null until the health loop has swept once — not "healthy". */
	health: Health | null;
}

export interface Overview {
	dashboard: {
		version: string;
		uptime_secs: number;
		uptime: string;
		total_connections: number;
		max_connections: number;
		databases: { name: string; size_bytes: number; connections: number; managed: boolean }[];
	} | null;
	maintenance: {
		findings: { severity: 'ok' | 'watch' | 'urgent'; title: string; summary: string; advice: string }[];
	} | null;
}

/** "unknown": could not be checked — never shown as fine. */
export interface Verdict {
	verdict: string;
	state: 'ok' | 'bad' | 'unknown';
}

export interface Edge {
	dirty: boolean;
	synced_at: string | null;
	hba: Verdict;
	knobs: Verdict;
	pools: { headers: string[]; rows: string[][] } | null;
}

export interface TestReport {
	checks: { check: string; ok: boolean; detail: string }[];
}

export interface DbPool {
	id: string;
	name: string;
	status: string;
	/** null: the server's mode applies. */
	pool_mode: string | null;
	/** null: the server's limit applies. */
	max_connections: number | null;
}

export interface Config {
	databases: DbPool[];
	sources: { id: string; label: string; cidr: string; is_default: boolean }[];
	listeners: { id: string; label: string; host: string; port: number }[];
}

/** What pushing a change to the edge did. */
export interface EdgeOutcome {
	state: 'applied' | 'manual' | 'failed';
	rules: number | null;
	hba: string | null;
	knobs: string | null;
	error: string | null;
}

/** As the server's EdgeSync::note words it: `what` was saved; did the edge take it?
 *  `failed` is for an alert, not a notice — saved is not applied. */
export function edgeNote(what: string, edge: EdgeOutcome): { failed: boolean; text: string } {
	if (edge.state === 'applied') return { failed: false, text: `${what} — edge synced.` };
	if (edge.state === 'manual')
		return { failed: false, text: `${what}. No conf dir — apply the change with "Sync edge now" (manual placement).` };
	return { failed: true, text: `${what}, but edge sync FAILED: ${edge.error ?? 'unknown error'}` };
}
