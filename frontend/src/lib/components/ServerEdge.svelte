<script lang="ts">
	// A server's Edge health: what the health loop last saw, whether the
	// rendered edge files match what they should be, the bouncer's own pool
	// stats, and the sync that puts them right. A check that could not be made
	// says so; it is never shown as fine.
	import { onMount, tick } from 'svelte';
	import { api } from '#lib/api.js';
	import { edgeNote, type Edge, type EdgeOutcome, type Server, type Verdict } from '#lib/admin-servers.js';
	import CopyButton from './CopyButton.svelte';
	import PageHeader from './PageHeader.svelte';
	import SettingRow from './SettingRow.svelte';

	let { server, onchanged }: { server: Server; onchanged: () => Promise<void> } = $props();
	const base = $derived(`/admin/servers/${encodeURIComponent(server.id)}`);

	let edge = $state<Edge | null>(null);
	let edgeError = $state<string | null>(null);
	// Rendered edge files for manual placement, from a sync: shown until the
	// page is left.
	let manual = $state<{ hba: string; knobs: string } | null>(null);
	let syncError = $state<string | null>(null);
	let syncNotice = $state<string | null>(null);
	let busy = $state(false);
	let alertEl = $state<HTMLElement>();
	let noticeEl = $state<HTMLElement>();

	// Each read carries its turn: the read the page opened with may land after
	// the one a sync asked for.
	let edgeTurn = 0;
	async function loadEdge() {
		const mine = ++edgeTurn;
		try {
			const e = await api<Edge>('GET', `${base}/edge`);
			if (mine === edgeTurn) [edge, edgeError] = [e, null];
		} catch (e) {
			if (mine === edgeTurn) edgeError = (e as Error).message;
		}
	}
	onMount(() => {
		loadEdge();
	});

	async function syncEdge() {
		if (busy) return;
		busy = true;
		syncError = syncNotice = null;
		manual = null;
		try {
			const r = await api<{ edge: EdgeOutcome }>('POST', `${base}/sync`);
			if (r.edge.state === 'applied') syncNotice = `Edge synced: ${r.edge.rules ?? 0} rule(s) applied.`;
			else if (r.edge.state === 'manual') {
				syncNotice = 'No conf dir: place these rendered files on the bouncer host, then reload it.';
				manual = { hba: r.edge.hba ?? '', knobs: r.edge.knobs ?? '' };
			} else syncError = edgeNote('Edge sync', r.edge).text.replace('Edge sync, but edge sync', 'Edge sync');
			await onchanged();
			loadEdge();
		} catch (e) {
			syncError = (e as Error).message;
		} finally {
			busy = false;
		}
		// The button was disabled while this ran: focus goes to what happened.
		await tick();
		(syncError ? alertEl : noticeEl)?.focus();
	}

	const when = (iso: string) => iso.slice(0, 19).replace('T', ' ') + ' UTC';
</script>

<PageHeader
	title="Edge health"
	desc="Whether the bouncer in front of this server is up, and enforcing the access rules Cryptarch rendered for it."
>
	{#snippet actions()}
		<button class="btn btn-primary" type="button" disabled={busy} onclick={syncEdge}>Sync edge now</button>
	{/snippet}
</PageHeader>
{#if syncError}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{syncError}</p>{/if}
{#if syncNotice}<p class="alert alert-ok" role="status" tabindex="-1" bind:this={noticeEl}>{syncNotice}</p>{/if}

{#if edgeError}
	<p class="alert alert-danger" role="alert">{edgeError}</p>
{:else if !edge}
	<p class="loading">Checking the edge…</p>
{:else}
	<div class="stack-6">
		<div class="card" id="edge-health">
			<SettingRow
				label="Live checks"
				desc={server.health ? `What the health loop saw ${server.health.checked_ago} ago.` : 'The health loop runs every interval after Cryptarch starts.'}
			>
				{#if !server.health}
					<span class="badge badge-unknown">No sweep yet</span>
				{:else}
					<span class="badges">
						{#each [['Edge listener', server.health.edge], ['Postgres', server.health.postgres], ...(server.health.drift ? [['Rendered files', server.health.drift] as const] : [])] as const as [label, c] (label)}
							<span class={c.ok ? 'badge badge-ok' : 'badge badge-danger'}>{label}{#if c.error}: {c.error}{/if}</span>
						{/each}
					</span>
				{/if}
			</SettingRow>
			<SettingRow
				label="Sync state"
				desc={edge.synced_at ? `Last good sync ${when(edge.synced_at)}.` : 'No good sync recorded yet.'}
			>
				{#if edge.dirty}
					<span class="badge badge-danger">Dirty: the last sync failed or is pending</span>
				{:else}
					<span class="badge badge-ok">Synced</span>
				{/if}
			</SettingRow>
			<SettingRow label="Rendered access file" desc="The hba file the bouncer reads, compared with what it should hold.">
				{@render verdict(edge.hba)}
			</SettingRow>
			<SettingRow label="Pool settings" desc="The pool settings file, compared with what it should hold.">
				{@render verdict(edge.knobs)}
			</SettingRow>
		</div>

		<div>
			<h2 class="section-title first">Bouncer pools</h2>
			{#if !edge.pools}
				<div class="card empty empty-blind" id="pools-unavailable">
					<h3>Console unavailable</h3>
					<p>The bouncer console is not configured or did not answer, so its pools could not be read.</p>
				</div>
			{:else if edge.pools.rows.length === 0}
				<div class="card empty" id="pools-none">
					<h3>No active pools</h3>
					<p>The console answered; nothing is connected through the edge right now.</p>
				</div>
			{:else}
				<div class="card table-wrap">
					<table class="table" id="bouncer-pools">
						<thead><tr>{#each edge.pools.headers as h, i (i)}<th>{h}</th>{/each}</tr></thead>
						<tbody>
							{#each edge.pools.rows as row, i (i)}
								<tr>{#each row as cell, j (j)}<td class="stamp">{cell}</td>{/each}</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>

		{#if manual}
			<section class="card" aria-labelledby="manual-h">
				<div class="card-head"><h2 id="manual-h">Files to place by hand</h2></div>
				<div class="card-body">
					<p class="lead">The rendered access file. Replace the bouncer's hba file with it.</p>
					<pre class="block" id="manual-hba">{manual.hba}</pre>
					<div class="btn-row"><CopyButton text={manual.hba} label="Copy the rendered access file" /></div>
					<p class="lead">
						The rendered pool settings. Save them as <code>cryptarch_bouncer.ini</code> in the bouncer's conf dir, and make
						<code>pgbouncer.ini</code> end with an <code>%include</code> of it.
					</p>
					<pre class="block" id="manual-knobs">{manual.knobs}</pre>
					<div class="btn-row"><CopyButton text={manual.knobs} label="Copy the rendered pool settings" /></div>
				</div>
			</section>
		{/if}
	</div>
{/if}

{#snippet verdict(v: Verdict)}
	{#if v.state === 'ok'}
		<span class="badge badge-ok">{v.verdict}</span>
	{:else if v.state === 'unknown'}
		<span class="badge badge-unknown">{v.verdict}</span>
	{:else}
		<span class="badge badge-warn">{v.verdict}</span>
	{/if}
{/snippet}
