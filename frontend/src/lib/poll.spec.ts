import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { poll } from './poll.js';

/** A document whose visibility the test controls. */
function fakeDoc() {
	const listeners = new Set<() => void>();
	return {
		hidden: false,
		addEventListener: (_: string, l: () => void) => listeners.add(l),
		removeEventListener: (_: string, l: () => void) => listeners.delete(l),
		show() {
			this.hidden = false;
			for (const l of [...listeners]) l();
		},
		listeners
	};
}

/** A server whose answers are queued: true = still running. */
function server(answers: (boolean | Error)[]) {
	const calls = { n: 0 };
	const fetch = vi.fn(async () => {
		calls.n++;
		const a = answers.shift() ?? false;
		if (a instanceof Error) throw a;
		return { running: a };
	});
	return { fetch, calls };
}

const flush = () => vi.advanceTimersByTimeAsync(0);

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

describe('poll', () => {
	it('fetches while running and stops once settled', async () => {
		const doc = fakeDoc();
		const { fetch, calls } = server([true, true, false]);
		const seen: boolean[] = [];
		poll({ fetch, running: (v) => v.running, onValue: (v) => seen.push(v.running), intervalMs: 1000, doc });
		await flush();
		expect(calls.n).toBe(1);
		await vi.advanceTimersByTimeAsync(1000);
		expect(calls.n).toBe(2);
		await vi.advanceTimersByTimeAsync(1000);
		expect(calls.n).toBe(3);
		await vi.advanceTimersByTimeAsync(10_000);
		expect(calls.n).toBe(3);
		expect(seen).toEqual([true, true, false]);
	});

	it('does not poll a hidden tab, and catches up when it is shown', async () => {
		const doc = fakeDoc();
		const { fetch, calls } = server([true, true, false]);
		poll({ fetch, running: (v) => v.running, onValue: () => {}, intervalMs: 1000, doc });
		await flush();
		doc.hidden = true;
		await vi.advanceTimersByTimeAsync(30_000);
		expect(calls.n).toBe(1);
		doc.show();
		await flush();
		expect(calls.n).toBe(2);
		expect(doc.listeners.size).toBe(0);
	});

	it('can wait an interval before its first fetch', async () => {
		const doc = fakeDoc();
		const { fetch, calls } = server([false]);
		poll({ fetch, running: (v) => v.running, onValue: () => {}, intervalMs: 1000, doc, waitFirst: true });
		await flush();
		expect(calls.n).toBe(0);
		await vi.advanceTimersByTimeAsync(1000);
		expect(calls.n).toBe(1);
	});

	it('keeps going through a failed fetch, and reports it', async () => {
		const doc = fakeDoc();
		const { fetch, calls } = server([true, new Error('blip'), false]);
		const errors: unknown[] = [];
		poll({ fetch, running: (v) => v.running, onValue: () => {}, onError: (e) => errors.push(e), intervalMs: 1000, doc });
		await vi.advanceTimersByTimeAsync(2000);
		expect(calls.n).toBe(3);
		expect(errors).toHaveLength(1);
	});

	it('stops for good on stop(), and drops an answer that lands after it', async () => {
		const doc = fakeDoc();
		let release!: (v: { running: boolean }) => void;
		const fetch = vi.fn(() => new Promise<{ running: boolean }>((r) => (release = r)));
		const onValue = vi.fn();
		const p = poll({ fetch, running: (v) => v.running, onValue, intervalMs: 1000, doc });
		p.stop();
		release({ running: true });
		await vi.advanceTimersByTimeAsync(10_000);
		expect(onValue).not.toHaveBeenCalled();
		expect(fetch).toHaveBeenCalledTimes(1);
		p.kick();
		expect(fetch).toHaveBeenCalledTimes(1);
	});

	it('keeps one request in flight: a kick during one waits, drops its answer, then asks again', async () => {
		const doc = fakeDoc();
		const pending: ((v: { running: boolean; n: number }) => void)[] = [];
		const fetch = vi.fn(() => new Promise<{ running: boolean; n: number }>((r) => pending.push(r)));
		const seen: number[] = [];
		const p = poll({ fetch, running: () => false, onValue: (v) => seen.push(v.n), intervalMs: 1000, doc });
		p.kick();
		p.kick();
		expect(fetch).toHaveBeenCalledTimes(1);
		pending[0]({ running: true, n: 1 });
		await flush();
		expect(fetch).toHaveBeenCalledTimes(2);
		pending[1]({ running: false, n: 2 });
		await vi.advanceTimersByTimeAsync(10_000);
		expect(seen).toEqual([2]);
		expect(fetch).toHaveBeenCalledTimes(2);
	});

	it('ignores a failure from a request a kick superseded, or one landing after stop', async () => {
		const doc = fakeDoc();
		const rejects: ((e: unknown) => void)[] = [];
		const fetch = vi.fn(
			() => new Promise<{ running: boolean }>((_, reject) => rejects.push(reject))
		);
		const onError = vi.fn();
		const p = poll({ fetch, running: () => false, onValue: () => {}, onError, intervalMs: 1000, doc });
		p.kick();
		rejects[0](new Error('stale'));
		await flush();
		expect(onError).not.toHaveBeenCalled();
		expect(fetch).toHaveBeenCalledTimes(2);
		p.stop();
		rejects[1](new Error('after stop'));
		await vi.advanceTimersByTimeAsync(10_000);
		expect(onError).not.toHaveBeenCalled();
		expect(fetch).toHaveBeenCalledTimes(2);
	});

	it('waits out a visibility event that leaves the tab hidden, and leaves no listener on stop', async () => {
		const doc = fakeDoc();
		const { fetch, calls } = server([true, true, true]);
		const p = poll({ fetch, running: (v) => v.running, onValue: () => {}, intervalMs: 1000, doc });
		await flush();
		doc.hidden = true;
		await vi.advanceTimersByTimeAsync(1000);
		expect(doc.listeners.size).toBe(1);
		for (const l of [...doc.listeners]) l(); // fired, but still hidden
		await flush();
		expect(calls.n).toBe(1);
		p.stop();
		expect(doc.listeners.size).toBe(0);
	});

	it('starts again on kick() after settling, ignoring the stale answer', async () => {
		const doc = fakeDoc();
		const { fetch, calls } = server([false, true, false]);
		const seen: boolean[] = [];
		const p = poll({ fetch, running: (v) => v.running, onValue: (v) => seen.push(v.running), intervalMs: 1000, doc });
		await flush();
		expect(calls.n).toBe(1);
		p.kick();
		await flush();
		await vi.advanceTimersByTimeAsync(1000);
		expect(calls.n).toBe(3);
		expect(seen).toEqual([false, true, false]);
	});
});
