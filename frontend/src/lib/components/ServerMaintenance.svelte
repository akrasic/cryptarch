<script lang="ts">
	// A server's Maintenance findings (CRYPTARCH-97). Each is a claim about the
	// server plus what to do about it: a panel that only shows numbers has
	// moved the work to the operator rather than done any of it. Asked of the
	// server when the page opens.
	import { onMount } from 'svelte';
	import { api } from '#lib/api.js';
	import type { Overview } from '#lib/admin-servers.js';
	import PageHeader from './PageHeader.svelte';

	let { serverId }: { serverId: string } = $props();

	let overview = $state<Overview | null>(null);
	let loadError = $state<string | null>(null);
	onMount(async () => {
		try {
			overview = await api<Overview>('GET', `/admin/servers/${encodeURIComponent(serverId)}/overview`);
		} catch (e) {
			loadError = (e as Error).message;
		}
	});

	// A severity this page does not know is shown as the most serious one,
	// never as fine.
	const SEV = {
		ok: { cls: 'finding finding-ok', badge: 'badge badge-ok', word: 'OK' },
		watch: { cls: 'finding finding-watch', badge: 'badge badge-warn', word: 'Watch' },
		urgent: { cls: 'finding finding-urgent', badge: 'badge badge-danger', word: 'Urgent' }
	} as const;
	const sev = (s: string) => (Object.hasOwn(SEV, s) ? SEV[s as keyof typeof SEV] : SEV.urgent);
</script>

<PageHeader
	title="Maintenance"
	desc="The ways a database stops working quietly. Most are one thing: something is preventing cleanup from running, so dead rows build up and the transaction budget drains. Checked when this page opens."
/>
{#if loadError}
	<p class="alert alert-danger" role="alert">{loadError}</p>
{:else if !overview}
	<p class="loading">Asking the server…</p>
{:else if !overview.maintenance}
	<div class="card empty empty-blind" id="maintenance-unavailable">
		<h2>Maintenance report unavailable</h2>
		<p>The managed server did not respond, or is not connected. Nothing here was ruled out.</p>
	</div>
{:else if overview.maintenance.findings.length === 0}
	<!-- Silent is not healthy: an engine that never looked has nothing to say. -->
	<div class="card empty empty-blind" id="maintenance-none">
		<h2>No checks from this engine</h2>
		<p>This engine does not report maintenance checks, so nothing here was looked at.</p>
	</div>
{:else}
	<div class="findings">
		{#each overview.maintenance.findings as f, i (i)}
			{@const s = sev(f.severity)}
			<section class={`card ${s.cls}`} aria-labelledby={`finding-${i}`}>
				<div class="card-head">
					<h2 id={`finding-${i}`}>{f.title}</h2>
					<span class={s.badge}>{s.word}</span>
				</div>
				<div class="card-body">
					<p class="lead">{f.summary}</p>
					<p class="finding-advice">{f.advice}</p>
				</div>
			</section>
		{/each}
	</div>
{/if}
