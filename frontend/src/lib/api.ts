// The JSON API client (CRYPTARCH-130; dec-cryptarch-sveltekit-architecture D4–D6).
//
// One wrapper so every request follows the same rules the server enforces:
// same-origin credentials (the HttpOnly session cookie — no token ever reaches
// this code), and JSON for anything that changes state. The server refuses a
// mutating request that is not `application/json` (that is its second CSRF
// lock), so a mutation with nothing to say still sends `{}`.

export class ApiError extends Error {
	readonly status: number;
	readonly code: string;

	constructor(status: number, code: string, message: string) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
		this.code = code;
	}
}

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface ApiOptions {
	/** Injected for tests; defaults to the global fetch. */
	fetch?: typeof fetch;
}

/** Calls `/api/v1{path}` and returns its JSON, or throws an {@link ApiError}. */
export async function api<T>(
	method: Method,
	path: string,
	body?: unknown,
	options: ApiOptions = {}
): Promise<T> {
	const doFetch = options.fetch ?? fetch;
	const mutating = method !== 'GET';
	const init: RequestInit = {
		method,
		credentials: 'same-origin',
		headers: { Accept: 'application/json' }
	};
	if (mutating) {
		init.headers = { ...init.headers, 'Content-Type': 'application/json' };
		init.body = JSON.stringify(body ?? {});
	}

	let res: Response;
	try {
		res = await doFetch(`/api/v1${path}`, init);
	} catch {
		throw new ApiError(0, 'network', 'Could not reach Cryptarch — check your connection.');
	}

	if (res.status === 204) return undefined as T;
	const data: unknown = await res.json().catch(() => null);
	if (!res.ok) {
		const err = (data as { error?: { code?: unknown; message?: unknown } } | null)?.error;
		throw new ApiError(
			res.status,
			typeof err?.code === 'string' ? err.code : 'http_' + res.status,
			typeof err?.message === 'string' ? err.message : `Request failed (${res.status}).`
		);
	}
	return data as T;
}

/** Who is signed in — `GET /api/v1/session`. */
export interface Me {
	username: string;
	is_admin: boolean;
	/** The password was set by an admin: every other endpoint refuses until
	 *  it is replaced (CRYPTARCH-146). */
	must_change_password: boolean;
}
