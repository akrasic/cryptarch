import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import ManageTab from './ManageTab.svelte';

const json = (status: number, body: unknown) =>
	new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function server(routes: Record<string, Response[]>) {
	const calls: { key: string; body: unknown }[] = [];
	vi.stubGlobal(
		'fetch',
		vi.fn(async (url: string, init?: RequestInit) => {
			const key = `${init?.method ?? 'GET'} ${url}`;
			calls.push({ key, body: init?.body ? JSON.parse(init.body as string) : undefined });
			const next = routes[key]?.shift();
			if (!next) throw new Error(`unexpected ${key}`);
			return next;
		})
	);
	return calls;
}

const settle = () => new Promise((r) => setTimeout(r, 0)).then(() => flushSync());
const PASSWORD = 'NewPasswordShownExactlyOnce00000';
const RESET = 'POST /api/v1/databases/alice_db/reset';
const DELETE = 'POST /api/v1/databases/alice_db/delete';

function open(isOwner = true, status = 'active') {
	const target = document.createElement('div');
	document.body.append(target);
	const ondeleted = vi.fn();
	const app = mount(ManageTab, { target, props: { name: 'alice_db', status, isOwner, ondeleted } });
	flushSync();
	return { app, target, ondeleted };
}

const button = (t: HTMLElement, text: string) =>
	[...t.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;

// The dialog's armed button, for both the reset and the delete confirm.
const confirmBtn = (t: HTMLElement) => t.querySelector<HTMLButtonElement>('.dialog button.btn-danger-solid')!;

function openDelete(t: HTMLElement) {
	button(t, 'Delete database…').click();
	flushSync();
}

function type(t: HTMLElement, value: string) {
	const input = t.querySelector<HTMLInputElement>('input[name=confirm]')!;
	input.value = value;
	input.dispatchEvent(new Event('input'));
	flushSync();
}

afterEach(() => {
	vi.unstubAllGlobals();
	document.body.innerHTML = '';
});

describe('ManageTab', () => {
	it('resets only after confirming, and shows the new password in place', async () => {
		const calls = server({
			[RESET]: [json(200, { name: 'alice_db', username: 'alice_db', password: PASSWORD, conn: `postgresql://alice_db:${PASSWORD}@h:5432/alice_db`, via: [], unrecorded: false })]
		});
		const { app, target } = open();
		button(target, 'Reset password').click();
		flushSync();
		button(target, 'Cancel').click();
		flushSync();
		expect(calls).toEqual([]);
		button(target, 'Reset password').click();
		flushSync();
		expect(target.querySelector('.dialog h2')?.textContent).toBe('Reset the password for alice_db?');
		expect(target.querySelector('.dialog p')?.textContent).toContain('The current password stops working immediately.');
		confirmBtn(target).click();
		await settle();
		expect(calls.map((c) => c.key)).toEqual([RESET]);
		// The button that asked is gone; focus is on the new credential.
		expect(document.activeElement).toBe(target.querySelector('section.once'));
		expect(target.textContent).toContain(PASSWORD);
		unmount(app);
	});

	it('forgets the password when the page is hidden', async () => {
		server({
			[RESET]: [json(200, { name: 'alice_db', username: 'alice_db', password: PASSWORD, conn: 'c', via: [], unrecorded: false })]
		});
		const { app, target } = open();
		button(target, 'Reset password').click();
		flushSync();
		confirmBtn(target).click();
		await settle();
		expect(target.textContent).toContain(PASSWORD);
		window.dispatchEvent(new Event('pagehide'));
		flushSync();
		expect(target.textContent).not.toContain(PASSWORD);
		unmount(app);
	});

	it('warns above the credential when the rotation was not recorded', async () => {
		server({
			[RESET]: [json(200, { name: 'alice_db', username: 'alice_db', password: PASSWORD, conn: 'c', via: [], unrecorded: true })]
		});
		const { app, target } = open();
		button(target, 'Reset password').click();
		flushSync();
		confirmBtn(target).click();
		await settle();
		expect(target.querySelector('[role=alert]')?.textContent).toContain('Saved on the server, not in Cryptarch.');
		expect(target.textContent).toContain(PASSWORD);
		unmount(app);
	});

	it('forgets the password on Done', async () => {
		server({
			[RESET]: [json(200, { name: 'alice_db', username: 'alice_db', password: PASSWORD, conn: 'c', via: [], unrecorded: false })]
		});
		const { app, target } = open();
		button(target, 'Reset password').click();
		flushSync();
		confirmBtn(target).click();
		await settle();
		expect(target.textContent).toContain(PASSWORD);
		button(target, "Done — I've saved it").click();
		flushSync();
		expect(target.textContent).not.toContain(PASSWORD);
		expect(button(target, 'Reset password')).toBeDefined();
		unmount(app);
	});

	it('clears an earlier failure once a reset succeeds', async () => {
		server({
			[RESET]: [
				json(500, { error: { code: 'reset_failed', message: 'Password reset failed: internal error' } }),
				json(200, { name: 'alice_db', username: 'alice_db', password: PASSWORD, conn: 'c', via: [], unrecorded: false })
			]
		});
		const { app, target } = open();
		for (let i = 0; i < 2; i++) {
			button(target, 'Reset password').click();
			flushSync();
			confirmBtn(target).click();
			await settle();
			if (i === 0) {
				expect(target.querySelector('[role=alert]')?.textContent).toBe('Password reset failed: internal error');
				expect(document.activeElement).toBe(target.querySelector('[role=alert]'));
			}
		}
		expect(target.textContent).toContain(PASSWORD);
		button(target, "Done — I've saved it").click();
		flushSync();
		expect(target.querySelector('[role=alert]')).toBeNull();
		unmount(app);
	});

	it('offers no reset while the database is not active', () => {
		server({});
		for (const status of ['deleting', 'restoring']) {
			const { app, target } = open(true, status);
			expect(button(target, 'Reset password')).toBeUndefined();
			expect(target.textContent).toContain(`Not while the database is ${status}.`);
			unmount(app);
		}
		const { app, target } = open(true, 'active');
		expect(button(target, 'Reset password')).toBeDefined();
		unmount(app);
	});

	it('sends one delete however fast it is clicked', async () => {
		let release!: (r: Response) => void;
		const calls: string[] = [];
		vi.stubGlobal(
			'fetch',
			vi.fn((url: string, init?: RequestInit) => {
				calls.push(`${init?.method} ${url}`);
				return new Promise<Response>((r) => (release = r));
			})
		);
		const { app, target, ondeleted } = open();
		openDelete(target);
		type(target, 'alice_db');
		const form = target.querySelector('.dialog form')!;
		const confirm = confirmBtn(target);
		confirm.click();
		form.dispatchEvent(new Event('submit', { cancelable: true }));
		confirm.click();
		await settle();
		expect(calls).toEqual([DELETE]);
		release(json(200, { deleted: 'alice_db', warning: null }));
		await settle();
		expect(ondeleted).toHaveBeenCalledOnce();
		unmount(app);
	});

	it('offers no reset to someone who does not own the database', () => {
		server({});
		const { app, target } = open(false);
		expect(button(target, 'Reset password')).toBeUndefined();
		expect(target.textContent).toContain('Only the owner can reset');
		expect(button(target, 'Delete database…')).toBeDefined();
		unmount(app);
	});

	it('arms delete only on the exact name, and sends what was typed', async () => {
		const calls = server({ [DELETE]: [json(200, { deleted: 'alice_db', warning: 'Edge sync FAILED' })] });
		const { app, target, ondeleted } = open();
		openDelete(target);
		const del = () => confirmBtn(target);
		expect(del().textContent).toBe('Delete alice_db');
		expect(del().disabled).toBe(true);
		for (const wrong of ['alice', 'alice_db2', 'ALICE_DB']) {
			type(target, wrong);
			expect(del().disabled, wrong).toBe(true);
		}
		// Sent exactly as typed: the server's check is only a check if it sees
		// what the user typed, not a name the page filled in.
		type(target, ' alice_db ');
		expect(del().disabled).toBe(false);
		del().click();
		await settle();
		expect(calls).toEqual([{ key: DELETE, body: { confirm: ' alice_db ' } }]);
		expect(ondeleted).toHaveBeenCalledWith('Edge sync FAILED');
		unmount(app);
	});

	it('does not delete on a submit that bypasses the disabled button', async () => {
		const calls = server({});
		const { app, target } = open();
		openDelete(target);
		type(target, 'alice_d');
		target.querySelector('.dialog form')!.dispatchEvent(new Event('submit', { cancelable: true }));
		await settle();
		expect(calls).toEqual([]);
		unmount(app);
	});

	it('shows a refused delete and stays put', async () => {
		server({
			[DELETE]: [json(500, { error: { code: 'delete_failed', message: 'Delete failed: internal error' } })]
		});
		const { app, target, ondeleted } = open();
		openDelete(target);
		type(target, 'alice_db');
		confirmBtn(target).click();
		await settle();
		expect(target.querySelector('[role=alert]')?.textContent).toBe('Delete failed: internal error');
		// The dialog is gone and its opener was disabled meanwhile: the refusal
		// holds focus, not the page.
		expect(document.activeElement).toBe(target.querySelector('[role=alert]'));
		expect(ondeleted).not.toHaveBeenCalled();
		expect(button(target, 'Delete database…').disabled).toBe(false);
		unmount(app);
	});
});
