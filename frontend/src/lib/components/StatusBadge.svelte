<script lang="ts" module>
	// What each status means, as a badge tone (the design system's StatusBadge).
	// Anything not listed renders as danger ON PURPOSE: a new status must not
	// quietly inherit a reassuring badge (CRYPTARCH-81).
	const TONE: Record<string, 'ok' | 'progress' | 'warn' | 'neutral' | 'unknown' | 'danger'> = {
		active: 'ok',
		ok: 'ok',
		ready: 'ok',
		verified: 'ok',
		recorded: 'ok',
		running: 'progress',
		pending: 'progress',
		restoring: 'progress',
		// Not progress: the row is marked before the DROP and never unmarked
		// if it fails, so a database still "deleting" is one whose delete
		// failed and waits for a retry (repair::FailedDelete).
		deleting: 'danger',
		needs_bootstrap: 'warn',
		// A user an admin suspended (a database is never suspended: CRYPTARCH-78).
		suspended: 'warn',
		unverified: 'warn',
		disabled: 'neutral',
		unknown: 'unknown'
	};

	export function toneOf(status: string): 'ok' | 'progress' | 'warn' | 'neutral' | 'unknown' | 'danger' {
		return Object.hasOwn(TONE, status) ? TONE[status] : 'danger';
	}

	/** "needs_bootstrap" → "Needs bootstrap"; "ok" → "OK". */
	export function labelOf(status: string): string {
		if (status === 'ok') return 'OK';
		const words = status.replace(/_/g, ' ');
		return words.charAt(0).toUpperCase() + words.slice(1);
	}
</script>

<script lang="ts">
	let { status, label, title }: { status: string; label?: string; title?: string } = $props();
	const tone = $derived(toneOf(status));
</script>

<span class={tone === 'neutral' ? 'badge' : `badge badge-${tone}`} {title}>{label ?? labelOf(status)}</span>
