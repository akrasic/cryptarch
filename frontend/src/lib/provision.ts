// The provision form's behaviour, as pure functions (originally app.js's
// wireCidrFollow) so it can be tested without a DOM.

export interface SourceOption {
	id: string;
	label: string;
	cidr: string;
	is_default: boolean;
}

export interface ServerOption {
	id: string;
	name: string;
	engine: string;
	default_cidr: string | null;
	sources: SourceOption[];
}

/**
 * What "Allowed from" should hold for `server` on first showing: the server's
 * default range, but only when it has no named sources — with sources, the
 * default is a ticked box instead.
 */
export function initialAllowedFrom(server: ServerOption | undefined): string {
	if (!server || server.sources.length > 0) return '';
	return server.default_cidr ?? '';
}

/**
 * "Allowed from" after the user switches server. Rewritten only while it still
 * holds the previous server's default — never over something they typed.
 */
export function allowedFromAfterSwitch(
	current: string,
	previous: ServerOption | undefined,
	next: ServerOption | undefined
): string {
	return current.trim() === initialAllowedFrom(previous).trim() ? initialAllowedFrom(next) : current;
}

/** The sources ticked by default on `server`. Other servers' never are. */
export function defaultSourceIds(server: ServerOption | undefined): string[] {
	return server?.sources.filter((s) => s.is_default).map((s) => s.id) ?? [];
}
