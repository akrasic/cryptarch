<script lang="ts" module>
	export interface RestoreStep {
		key: string;
		title: string;
		blurb: string;
		state: 'done' | 'running' | 'failed' | 'skipped' | 'pending';
		time: string | null;
		detail: string | null;
		error: string | null;
	}
	export interface RestoreJob {
		id: string;
		created_at: string;
		finished_at: string | null;
		status: string;
		requested_by: string;
		error: string | null;
		steps: RestoreStep[];
	}
</script>

<script lang="ts">
	// The five-step restore pipeline, each step's state from the
	// server's one derivation (RestoreRow::step_state), followed every 2s
	// while it runs (lib/poll).
	import { onMount, untrack } from 'svelte';
	import { api, ApiError } from '#lib/api.js';
	import { poll } from '#lib/poll.js';
	import SettingRow from './SettingRow.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let { name, initial }: { name: string; initial: RestoreJob } = $props();
	let job = $state(untrack(() => initial));
	let loadError = $state<string | null>(null);

	onMount(() => {
		if (job.status !== 'running') return;
		const p = poll<RestoreJob>({
			fetch: () =>
				api('GET', `/databases/${encodeURIComponent(name)}/restores/${encodeURIComponent(job.id)}`),
			running: (j) => j.status === 'running',
			intervalMs: 2000,
			// The page's load just fetched it.
			waitFirst: true,
			onValue: (j) => ([job, loadError] = [j, null]),
			onError: (e) => {
				loadError = (e as Error).message;
				// Signed out, or the database is gone: the answer will not change.
				if (e instanceof ApiError && [401, 403, 404].includes(e.status)) p.stop();
			}
		});
		return () => p.stop();
	});

	// Done and failed say how it went; the rest carry their step's number.
	const mark = (state: RestoreStep['state'], i: number) =>
		state === 'done' ? '✓' : state === 'failed' ? '✕' : state === 'skipped' ? '–' : String(i + 1);
	const started = (iso: string) => iso.slice(0, 16).replace('T', ' ') + ' UTC';
</script>

{#if loadError}<p class="alert alert-danger" role="alert">{loadError}</p>{/if}
<div class="stack-6">
	<div class="card">
		<SettingRow label="Status" desc={`Started ${started(job.created_at)} by ${job.requested_by}.`}>
			<StatusBadge status={job.status} />
		</SettingRow>
	</div>
	<div class="card job-steps" id="restorejob">
		<ol class="steps">
			{#each job.steps as s, i (s.key)}
				<li class={`step step-${s.state}`}>
					<span class="step-mark" aria-hidden="true">{mark(s.state, i)}</span>
					<div class="step-body">
						<div class="step-head">
							<span class="step-title">{s.title}</span>
							{#if s.time}<span class="step-time">{s.time}</span>{/if}
						</div>
						<p class="step-blurb">{s.blurb}</p>
						{#if s.detail}<p class="step-detail"><code>{s.detail}</code></p>{/if}
						{#if s.state === 'failed' && s.error}<p class="step-error">{s.error}</p>{/if}
						{#if s.state === 'skipped'}
							<p class="step-note">Never ran: an earlier step failed, so the database was never touched.</p>
						{/if}
					</div>
				</li>
			{/each}
		</ol>
		{#if job.status === 'failed' && job.error && !job.steps.some((s) => s.state === 'failed')}
			<!-- No step owns it (a stage this build does not know): still said. -->
			<p class="step-error">{job.error}</p>
		{/if}
		{#if job.status === 'ok'}
			<p class="step-outcome">This database now holds the contents of that backup.</p>
		{:else if job.status === 'failed'}
			<p class="step-outcome">
				Nothing changed. The transaction never committed, so the database still holds exactly what it
				held before.
			</p>
		{:else}
			<p class="step-outcome">Running. Your database is unchanged until the whole dump commits.</p>
		{/if}
	</div>
</div>
