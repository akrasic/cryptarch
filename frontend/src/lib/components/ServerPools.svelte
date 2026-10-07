<script lang="ts">
	// A server's Pools page: per
	// database, its own pool mode or connection cap, or the server's.
	import { tick } from 'svelte';
	import { api } from '#lib/api.js';
	import { edgeNote, type DbPool, type EdgeOutcome } from '#lib/admin-servers.js';
	import PageHeader from './PageHeader.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let {
		serverId,
		poolMode,
		maxUserConnections,
		databases,
		onchanged
	}: { serverId: string; poolMode: string; maxUserConnections: number; databases: DbPool[]; onchanged: () => Promise<void> } =
		$props();

	// The edited values, per database id; seeded from what is stored. The
	// limit is a text field parsed here: a number input reports junk ("1e",
	// "-") as empty, which would be sent as "inherit".
	let edits = $state<Record<string, { mode: string; max: string }>>({});
	$effect(() => {
		edits = Object.fromEntries(
			databases.map((d) => [d.id, { mode: d.pool_mode ?? 'inherit', max: d.max_connections?.toString() ?? '' }])
		);
	});
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	let alertEl = $state<HTMLElement>();
	let noticeEl = $state<HTMLElement>();

	async function apply(d: DbPool) {
		if (busy) return;
		busy = true;
		error = notice = null;
		const e = edits[d.id];
		const raw = e.max.trim();
		if (raw !== '' && !/^[0-9]+$/.test(raw)) {
			error = `Connection limit for ${d.name} must be a whole number, or empty to inherit.`;
			busy = false;
			await tick();
			alertEl?.focus();
			return;
		}
		try {
			const r = await api<{ name: string; edge: EdgeOutcome }>(
				'POST',
				`/admin/servers/${encodeURIComponent(serverId)}/databases/${encodeURIComponent(d.id)}/pool`,
				{ pool_mode: e.mode, max_connections: raw === '' ? null : Number(raw) }
			);
			const n = edgeNote(`Override for ${r.name} saved`, r.edge);
			if (n.failed) error = n.text;
			else notice = n.text;
			await onchanged();
		} catch (err) {
			error = (err as Error).message;
			// Not on this server any more: the list on screen is stale.
			if ((err as { code?: string }).code === 'no_such_item') await onchanged();
		} finally {
			busy = false;
		}
		// Apply was disabled while this ran: focus goes to the answer.
		await tick();
		(error ? alertEl : noticeEl)?.focus();
	}
</script>

<PageHeader
	title="Pools"
	desc={`This server pools connections in ${poolMode} mode and allows ${maxUserConnections === 0 ? 'unlimited' : maxUserConnections} Postgres connections per user (the defaults are in Settings). A database here can differ: its own pool mode, or a cap on the Postgres connections it holds at once. Inherit, or an empty limit, keeps the server default. Apply pushes the change to the edge immediately.`}
/>
{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status" tabindex="-1" bind:this={noticeEl}>{notice}</p>{/if}
{#if databases.length === 0}
	<div class="card empty" id="pools-empty">
		<h2>No databases on this server yet</h2>
		<p>Each one provisioned here gets a row, to give it a pool of its own.</p>
	</div>
{:else}
	<div class="card table-wrap">
		<table class="table" id="pool-overrides">
			<thead><tr><th>Database</th><th>Pool mode</th><th>Connection limit</th><th><span class="sr-only">Actions</span></th></tr></thead>
			<tbody>
				{#each databases as d (d.id)}
					{#if edits[d.id]}
						<tr>
							<td><code>{d.name}</code>{#if d.status !== 'active'}&nbsp;<StatusBadge status={d.status} />{/if}</td>
							<td>
								<select class="input" name="pool_mode" aria-label={`Pool mode for ${d.name}`} bind:value={edits[d.id].mode}>
									<option value="inherit">Inherit</option>
									<option value="session">Session</option>
									<option value="transaction">Transaction</option>
								</select>
							</td>
							<td>
								<input class="input mono-text input-narrow" type="text" inputmode="numeric" name="max_connections"
									aria-label={`Connection limit for ${d.name}`} placeholder="inherit" bind:value={edits[d.id].max} />
							</td>
							<td class="act">
								<button class="btn btn-sm" type="button" disabled={busy} aria-label={`Apply pool override for ${d.name}`}
									onclick={() => apply(d)}>Apply</button>
							</td>
						</tr>
					{/if}
				{/each}
			</tbody>
		</table>
	</div>
{/if}
