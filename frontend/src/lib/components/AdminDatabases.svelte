<script lang="ts" module>
	export interface FleetDb {
		name: string;
		status: string;
		owner: string;
		server_name: string;
		last_backup: { at: string; status: string; verified: boolean } | null;
	}
</script>

<script lang="ts">
	// Every database, its owner and its last backup.
	import type { Snippet } from 'svelte';
	import PageHeader from './PageHeader.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let {
		databases,
		dbHref,
		children
	}: {
		databases: FleetDb[];
		dbHref: (name: string) => string;
		/** Alerts for this page, shown under its header. */
		children?: Snippet;
	} = $props();
	const when = (iso: string) => iso.slice(0, 16).replace('T', ' ') + ' UTC';
</script>

<PageHeader
	title="All databases"
	desc="Every database on every server, its owner and its last backup. Open one to manage it as an administrator."
/>
{@render children?.()}
{#if databases.length === 0}
	<div class="card empty" id="no-databases">
		<h2>No databases yet</h2>
		<p>None has been provisioned on any server.</p>
	</div>
{:else}
	<div class="card table-wrap">
		<table class="table" id="fleet">
			<thead><tr><th>Database</th><th>Owner</th><th>Server</th><th>Status</th><th>Last backup</th></tr></thead>
			<tbody>
				{#each databases as d (d.name)}
					<tr>
						<td><a class="row-link" href={dbHref(d.name)}>{d.name}</a></td>
						<td>{d.owner}</td>
						<td class="sub">{d.server_name}</td>
						<td><StatusBadge status={d.status} /></td>
						<td>
							{#if d.last_backup}
								<span class="when">{when(d.last_backup.at)}</span>
								<span class="badges">
									<StatusBadge status={d.last_backup.status} />
									{#if d.last_backup.status === 'ok' && !d.last_backup.verified}
										<StatusBadge status="unverified" title="Written but never read back." />
									{/if}
								</span>
							{:else}
								<!-- "never" is the finding, not a blank cell to skim past. -->
								<span class="badge badge-warn">Never</span>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
