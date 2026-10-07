<script lang="ts">
	// The server list. Health is the loop's last sweep; before the first
	// one it says so, rather than reading as healthy.
	import type { Server } from '#lib/admin-servers.js';
	import PageHeader from './PageHeader.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let {
		servers,
		serverHref,
		settingsHref,
		addHref
	}: {
		servers: Server[];
		serverHref: (id: string) => string;
		settingsHref: (id: string) => string;
		addHref: string;
	} = $props();
</script>

<PageHeader
	title="Servers"
	desc="The database servers Cryptarch provisions onto. Health is the last background check, not a live one."
>
	{#snippet actions()}<a class="btn btn-primary" href={addHref}>Add server</a>{/snippet}
</PageHeader>
{#if servers.length === 0}
	<div class="card empty" id="no-servers">
		<h2>No servers yet</h2>
		<p>Add the first: Cryptarch needs one to provision any database.</p>
	</div>
{:else}
	<div class="card table-wrap">
		<table class="table" id="servers">
			<thead>
				<tr>
					<th>Server</th><th>Engine</th><th>Advertised</th><th class="num">Databases</th><th>Pool</th><th>Status</th
					><th>Health</th><th><span class="sr-only">Actions</span></th>
				</tr>
			</thead>
			<tbody>
				{#each servers as s (s.id)}
					<tr>
						<td><a class="row-link" href={serverHref(s.id)}>{s.name}</a></td>
						<td class="sub">{s.engine}</td>
						<td><code>{s.host}:{s.port}</code></td>
						<td class="num">{s.db_count}</td>
						<td class="sub">{s.pool_mode}</td>
						<td><StatusBadge status={s.status} /></td>
						<td>
							{#if !s.health}
								<StatusBadge status="unknown" label="No data yet" title="The background check has not run since Cryptarch started." />
							{:else if s.health.all_ok}
								<span class="badge badge-ok">Healthy</span>
							{:else}
								<span class="badge badge-danger">Attention</span>
							{/if}
						</td>
						<td class="act">
							<a class="btn btn-quiet btn-sm" href={settingsHref(s.id)} aria-label={`Settings for server ${s.name}`}>Settings</a>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
