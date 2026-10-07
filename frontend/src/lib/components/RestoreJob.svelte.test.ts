import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import RestoreJob, { type RestoreJob as Job, type RestoreStep } from './RestoreJob.svelte';

const KEYS = ['locating', 'checking', 'connecting', 'loading', 'finishing'];
const job = (status: string, states: RestoreStep['state'][], extra: Partial<RestoreStep>[] = []): Job => ({
	id: 'job1',
	created_at: '2026-10-07T10:00:00Z',
	finished_at: status === 'running' ? null : '2026-10-07T10:01:00Z',
	status,
	requested_by: 'alice',
	error: extra.find((e) => e.error)?.error ?? null,
	steps: KEYS.map((key, i) => ({
		key,
		title: `Step ${key}`,
		blurb: `Why ${key}`,
		state: states[i],
		time: null,
		detail: null,
		error: null,
		...(extra[i] ?? {})
	}))
});
const json = (body: unknown) =>
	new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
const JOB = 'GET /api/v1/databases/alice_db/restores/job1';

function server(answers: Job[]) {
	const calls: string[] = [];
	vi.stubGlobal(
		'fetch',
		vi.fn(async (url: string, init?: RequestInit) => {
			calls.push(`${init?.method ?? 'GET'} ${url}`);
			const next = answers.shift();
			if (!next) throw new Error('unexpected');
			return json(next);
		})
	);
	return calls;
}

function open(initial: Job) {
	const target = document.createElement('div');
	document.body.append(target);
	const app = mount(RestoreJob, { target, props: { name: 'alice_db', initial } });
	flushSync();
	return { app, target, cls: () => [...target.querySelectorAll('li.step')].map((l) => l.className) };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllGlobals();
	document.body.innerHTML = '';
});

describe('RestoreJob', () => {
	it('draws each step as the server derived it, the error on the failed one', () => {
		server([]);
		const { app, target, cls } = open(
			job('failed', ['done', 'done', 'done', 'failed', 'skipped'], [
				{ time: '10:00:01Z', detail: 'found x.enc' },
				{},
				{},
				{ error: 'pg_restore: error: boom' }
			])
		);
		expect(cls()).toEqual(['step step-done', 'step step-done', 'step step-done', 'step step-failed', 'step step-skipped']);
		const steps = [...target.querySelectorAll('li.step')];
		// How it went where it went somewhere, the step's number otherwise.
		expect(steps.map((s) => s.querySelector('.step-mark')?.textContent)).toEqual(['✓', '✓', '✓', '✕', '–']);
		expect(steps[0].querySelector('.step-detail code')?.textContent).toBe('found x.enc');
		expect(steps[0].querySelector('.step-time')?.textContent).toBe('10:00:01Z');
		expect(steps[3].querySelector('.step-error')?.textContent).toBe('pg_restore: error: boom');
		expect(steps[4].textContent).toContain('Never ran');
		expect(target.querySelector('.step-outcome')?.textContent).toContain('Nothing changed');
		unmount(app);
	});

	it('numbers the steps still to come and the one running', () => {
		server([]);
		const { app, target } = open(job('running', ['done', 'running', 'pending', 'pending', 'pending']));
		const marks = [...target.querySelectorAll('li.step .step-mark')].map((m) => m.textContent);
		expect(marks).toEqual(['✓', '2', '3', '4', '5']);
		unmount(app);
	});

	it('shows an error only on the failed step', () => {
		server([]);
		const { app, target } = open(
			job('failed', ['done', 'failed', 'skipped', 'skipped', 'skipped'], [
				{ error: 'not this one' },
				{ error: 'pg_restore: error: boom' }
			])
		);
		const errors = [...target.querySelectorAll('.step-error')].map((e) => e.textContent);
		expect(errors).toEqual(['pg_restore: error: boom']);
		unmount(app);
	});

	it('still says the error when no step owns it', () => {
		server([]);
		const unknown = job('failed', ['pending', 'pending', 'pending', 'pending', 'pending']);
		const { app, target } = open({ ...unknown, error: 'restore abandoned by a restart' });
		expect(target.querySelector('.step-error')?.textContent).toBe('restore abandoned by a restart');
		unmount(app);
	});

	it('stops asking once the answer cannot change, and when it goes away', async () => {
		const calls: string[] = [];
		vi.stubGlobal(
			'fetch',
			vi.fn(async (url: string) => {
				calls.push(url);
				return new Response(JSON.stringify({ error: { code: 'not_found', message: 'There is no database by that name.' } }), {
					status: 404,
					headers: { 'Content-Type': 'application/json' }
				});
			})
		);
		const a = open(job('running', ['done', 'running', 'pending', 'pending', 'pending']));
		await vi.advanceTimersByTimeAsync(20_000);
		flushSync();
		expect(calls).toHaveLength(1);
		expect(a.target.querySelector('[role=alert]')?.textContent).toBe('There is no database by that name.');
		unmount(a.app);

		const ok = server([job('running', ['done', 'running', 'pending', 'pending', 'pending'])]);
		const b = open(job('running', ['done', 'running', 'pending', 'pending', 'pending']));
		unmount(b.app);
		await vi.advanceTimersByTimeAsync(20_000);
		expect(ok).toEqual([]);
	});

	it('follows a running restore every 2s until it settles, then stops', async () => {
		const calls = server([
			job('running', ['done', 'done', 'done', 'running', 'pending']),
			job('ok', ['done', 'done', 'done', 'done', 'done'])
		]);
		const { app, target, cls } = open(job('running', ['done', 'done', 'running', 'pending', 'pending']));
		expect(target.querySelector('.step-outcome')?.textContent).toContain('Running');
		await vi.advanceTimersByTimeAsync(0);
		// The load already fetched it: no second fetch on mount.
		expect(calls).toEqual([]);
		await vi.advanceTimersByTimeAsync(2000);
		flushSync();
		expect(cls()[3]).toBe('step step-running');
		await vi.advanceTimersByTimeAsync(2000);
		flushSync();
		expect(cls()).toEqual(Array(5).fill('step step-done'));
		expect(target.querySelector('.step-outcome')?.textContent).toContain('now holds the contents');
		await vi.advanceTimersByTimeAsync(20_000);
		expect(calls).toEqual([JOB, JOB]);
		unmount(app);
	});

	it('does not ask again about a finished restore', async () => {
		const calls = server([]);
		const { app } = open(job('ok', ['done', 'done', 'done', 'done', 'done']));
		await vi.advanceTimersByTimeAsync(20_000);
		expect(calls).toEqual([]);
		unmount(app);
	});
});
