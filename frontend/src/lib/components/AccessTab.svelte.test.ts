import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import AccessTab from './AccessTab.svelte';

const entry = (id: string, cidr: string) => ({ id, cidr, created_by: 'alice', note: null });
const list = (...entries: ReturnType<typeof entry>[]) => ({ entries, unallowed_sources: [] });
const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

/** A fetch that answers from a queue per "METHOD path", and records each call. */
function server(routes: Record<string, (Response | Promise<Response>)[]>) {
	const calls: string[] = [];
	const fetch = vi.fn(async (url: string, init?: RequestInit) => {
		const key = `${init?.method ?? 'GET'} ${url}`;
		calls.push(key);
		const next = routes[key]?.shift();
		if (!next) throw new Error(`unexpected ${key}`);
		return next;
	});
	vi.stubGlobal('fetch', fetch);
	return calls;
}

const settle = () => new Promise((r) => setTimeout(r, 0)).then(() => flushSync());
const LIST = 'GET /api/v1/databases/alice_db/acl';
const ADD = 'POST /api/v1/databases/alice_db/acl';

async function open(onchange = vi.fn(async () => {})) {
	const target = document.createElement('div');
	document.body.append(target);
	const app = mount(AccessTab, { target, props: { name: 'alice_db', onchange } });
	await settle();
	await settle();
	return { app, target, onchange };
}

async function allow(target: HTMLElement, value: string) {
	const input = target.querySelector<HTMLInputElement>('input[name=cidr]')!;
	input.value = value;
	input.dispatchEvent(new Event('input'));
	target.querySelector<HTMLButtonElement>('button.btn-primary')!.click();
	await settle();
	await settle();
}

afterEach(() => {
	vi.unstubAllGlobals();
	document.body.innerHTML = '';
});

describe('AccessTab', () => {
	it('shows what the server re-reads after a change, not a local guess', async () => {
		const calls = server({
			[LIST]: [json(200, list(entry('a', '10.0.0.0/24'))), json(200, list(entry('a', '10.0.0.0/24'), entry('b', '10.9.0.0/16')))],
			[ADD]: [json(201, { created: true, warning: null, entry: entry('b', '10.9.0.0/16') })]
		});
		const { app, target, onchange } = await open();
		expect(target.textContent).toContain('10.0.0.0/24');
		expect(target.textContent).not.toContain('10.9.0.0/16');
		await allow(target, '10.9.0.0/16');
		expect(calls).toEqual([LIST, ADD, LIST]);
		expect(target.textContent).toContain('10.9.0.0/16');
		expect(target.querySelector('[role=status]')?.textContent).toBe('Source allowed.');
		expect(onchange).toHaveBeenCalledOnce();
		unmount(app);
	});

	it('says when the edge did not take the change', async () => {
		server({
			[LIST]: [json(200, list()), json(200, list(entry('b', '10.9.0.0/16')))],
			[ADD]: [json(201, { created: true, warning: 'Edge sync FAILED — access rules not applied', entry: entry('b', '10.9.0.0/16') })]
		});
		const { app, target } = await open();
		await allow(target, '10.9.0.0/16');
		const alerts = [...target.querySelectorAll('[role=alert]')].map((e) => e.textContent);
		expect(alerts).toContain('Edge sync FAILED — access rules not applied');
		unmount(app);
	});

	it('tells an existing source apart from a new one', async () => {
		server({
			[LIST]: [json(200, list(entry('a', '10.0.0.0/24'))), json(200, list(entry('a', '10.0.0.0/24')))],
			[ADD]: [json(200, { created: false, warning: null, entry: entry('a', '10.0.0.0/24') })]
		});
		const { app, target } = await open();
		await allow(target, '10.0.0.0/24');
		expect(target.querySelector('[role=status]')?.textContent).toBe('Already allowed — nothing changed.');
		unmount(app);
	});

	it('shows a refusal in the server’s words and keeps the list', async () => {
		server({
			[LIST]: [json(200, list(entry('a', '10.0.0.0/24'))), json(200, list(entry('a', '10.0.0.0/24')))],
			[ADD]: [json(422, { error: { code: 'bad_cidr', message: "'nope' is not a valid IP or CIDR" } })]
		});
		const { app, target } = await open();
		await allow(target, 'nope');
		expect(target.querySelector('[role=alert]')?.textContent).toBe("'nope' is not a valid IP or CIDR");
		expect(target.querySelector('[role=status]')).toBeNull();
		expect(target.textContent).toContain('10.0.0.0/24');
		unmount(app);
	});

	it('keeps every control disabled until the re-read lands', async () => {
		let release!: (r: Response) => void;
		server({
			[LIST]: [json(200, list(entry('a', '10.0.0.0/24'))), new Promise<Response>((r) => (release = r))],
			[ADD]: [json(201, { created: true, warning: null, entry: entry('b', '10.9.0.0/16') })]
		});
		const { app, target } = await open();
		const buttons = () => [...target.querySelectorAll('button')];
		expect(buttons().some((b) => b.disabled)).toBe(false);
		await allow(target, '10.9.0.0/16');
		expect(buttons().length).toBeGreaterThan(1);
		expect(buttons().every((b) => b.disabled)).toBe(true);
		release(json(200, list(entry('a', '10.0.0.0/24'), entry('b', '10.9.0.0/16'))));
		await settle();
		await settle();
		expect(buttons().some((b) => b.disabled)).toBe(false);
		unmount(app);
	});

	it('removes only after confirming, and only the entry asked about', async () => {
		const DEL = 'DELETE /api/v1/databases/alice_db/acl/b';
		const calls = server({
			[LIST]: [json(200, list(entry('a', '10.0.0.0/24'), entry('b', '10.9.0.0/16'))), json(200, list(entry('a', '10.0.0.0/24')))],
			[DEL]: [json(200, { removed: '10.9.0.0/16', warning: null })]
		});
		const { app, target } = await open();
		const remove = () => target.querySelector<HTMLButtonElement>('button[aria-label="Remove source 10.9.0.0/16"]')!;
		remove().click();
		flushSync();
		expect(target.querySelector('.dialog h2')?.textContent).toBe('Remove 10.9.0.0/16?');
		expect(target.querySelector('.dialog p')?.textContent).toBe('Clients there lose access at the edge immediately.');
		target.querySelector<HTMLButtonElement>('.dialog button:not(.btn-danger-solid)')!.click();
		flushSync();
		expect(target.querySelector('.dialog')).toBeNull();
		expect(calls).toEqual([LIST]);
		remove().click();
		flushSync();
		target.querySelector<HTMLButtonElement>('.dialog button.btn-danger-solid')!.click();
		await settle();
		await settle();
		expect(calls).toEqual([LIST, DEL, LIST]);
		expect(target.textContent).not.toContain('10.9.0.0/16');
		expect(target.querySelector('[role=status]')?.textContent).toBe('Source removed.');
		unmount(app);
	});
});
