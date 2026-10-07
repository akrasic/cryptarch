// Following a job while it runs (dec-cryptarch-sveltekit-architecture D9) —
// re-asking every few seconds while something is still running.
//
// Fetch now; while the answer says something is still running, fetch again
// after `intervalMs`; once it has settled, stop. A hidden tab does not poll —
// it waits for the tab to be shown again and fetches then. A failed fetch is
// reported and retried on the same schedule: a blip must not freeze a page on
// "running" forever. `kick()` starts it again (a new job was just started);
// `stop()` ends it, and a result that lands after stop is dropped. At most one
// request is ever in flight: a kick during one waits for it, discards its
// answer, then asks again.

export interface PollOptions<T> {
	fetch: () => Promise<T>;
	running: (value: T) => boolean;
	onValue: (value: T) => void;
	onError?: (error: unknown) => void;
	intervalMs?: number;
	/** Wait one interval before the first fetch — for a caller that already
	 *  holds a fresh answer (a page's load). */
	waitFirst?: boolean;
	/** Injected for tests; defaults to the global document. */
	doc?: VisibilityDoc;
}

/** The slice of `document` this needs. */
export interface VisibilityDoc {
	readonly hidden: boolean;
	addEventListener(type: 'visibilitychange', listener: () => void): void;
	removeEventListener(type: 'visibilitychange', listener: () => void): void;
}

export interface Poller {
	kick: () => void;
	stop: () => void;
}

export function poll<T>(opts: PollOptions<T>): Poller {
	const interval = opts.intervalMs ?? 3000;
	const doc = opts.doc ?? document;
	let timer: ReturnType<typeof setTimeout> | null = null;
	let stopped = false;
	// Each fetch carries the generation it was started in; kick() and stop()
	// move it on, so an answer from before either is ignored.
	let generation = 0;
	let waitingForVisible = false;
	let inFlight = false;
	// A kick arrived while a request was in flight: ask again when it lands.
	let kickPending = false;

	const onVisible = () => {
		if (!doc.hidden && waitingForVisible) {
			waitingForVisible = false;
			doc.removeEventListener('visibilitychange', onVisible);
			tick();
		}
	};

	function schedule() {
		if (stopped) return;
		timer = setTimeout(() => {
			timer = null;
			if (doc.hidden) {
				waitingForVisible = true;
				doc.addEventListener('visibilitychange', onVisible);
			} else {
				tick();
			}
		}, interval);
	}

	function tick() {
		const mine = generation;
		inFlight = true;
		const settled = () => {
			inFlight = false;
			if (mine === generation) return true;
			// Superseded by a kick: its answer is stale, and the kick is owed.
			if (kickPending && !stopped) {
				kickPending = false;
				tick();
			}
			return false;
		};
		opts.fetch().then(
			(value) => {
				if (!settled() || stopped) return;
				opts.onValue(value);
				if (opts.running(value)) schedule();
			},
			(error) => {
				if (!settled() || stopped) return;
				opts.onError?.(error);
				schedule();
			}
		);
	}

	function clear() {
		generation++;
		if (timer) clearTimeout(timer);
		timer = null;
		if (waitingForVisible) {
			waitingForVisible = false;
			doc.removeEventListener('visibilitychange', onVisible);
		}
	}

	if (opts.waitFirst) schedule();
	else tick();
	return {
		kick() {
			if (stopped) return;
			clear();
			if (inFlight) kickPending = true;
			else tick();
		},
		stop() {
			stopped = true;
			clear();
		}
	};
}
