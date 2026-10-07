<script lang="ts" module>
	export interface Contents {
		available: boolean;
		size_bytes?: number;
		active?: boolean;
		/** null: the table list could not be read, which is not "no tables". */
		tables?: { name: string; approx_rows: number; total_bytes: number }[] | null;
	}
</script>

<script lang="ts">
	// A database's Contents page, once the server has answered (or not):
	// unavailable, unreadable and empty are three different things, and only
	// the last is an empty state; the other two say Cryptarch could not see.
	import { humanBytes } from '#lib/format.js';
	import SettingRow from './SettingRow.svelte';

	let { contents }: { contents: Contents | null } = $props();
</script>

{#if !contents || !contents.available}
	<div class="card empty empty-blind" id="contents-unavailable">
		<h2>Contents unavailable</h2>
		<p>The server did not answer, so nothing is known about what is in this database. Refresh to ask again.</p>
	</div>
{:else}
	{@const c = contents}
	<div class="stack-6">
		<div class="card">
			<SettingRow label="Size on disk" desc="Tables, indexes and everything else, as the server counts it.">
				<span class="setting-value">{humanBytes(c.size_bytes ?? 0)}</span>
			</SettingRow>
			<SettingRow label="In use" desc="Whether anything is connected to it right now.">
				<span class="setting-value">{c.active ? 'In use now' : 'Idle'}</span>
			</SettingRow>
		</div>
		{#if !c.tables}
			<div class="card empty empty-blind">
				<h2>The table list isn't readable</h2>
				<p>The server answered, but would not list this database's tables. There may be tables here; Cryptarch cannot see them.</p>
			</div>
		{:else if c.tables.length === 0}
			<div class="card empty">
				<h2>No tables yet</h2>
				<p>Connect with your credentials and create your first.</p>
			</div>
		{:else}
			<div>
				<div class="card table-wrap">
					<table class="table">
						<thead><tr><th>Table</th><th class="num">Rows (approx.)</th><th class="num">Size</th></tr></thead>
						<tbody>
							{#each c.tables as t, i (i)}
								<tr>
									<td><code>{t.name}</code></td>
									<!-- reltuples = -1: never analyzed, not "minus one row". -->
									<td class="num">{t.approx_rows < 0 ? '—' : t.approx_rows}</td>
									<td class="num">{humanBytes(t.total_bytes)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
				<p class="table-note">
					{c.tables.length} table{c.tables.length === 1 ? '' : 's'}. Row counts are the planner's estimates;
					sizes include indexes.
				</p>
			</div>
		{/if}
	</div>
{/if}
