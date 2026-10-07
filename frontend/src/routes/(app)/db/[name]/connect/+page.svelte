<script lang="ts">
	import CopyButton from '#lib/components/CopyButton.svelte';
	import EdgeDirtyAlert from '#lib/components/EdgeDirtyAlert.svelte';
	import PageHeader from '#lib/components/PageHeader.svelte';
	import SettingRow from '#lib/components/SettingRow.svelte';
	import { section } from '#lib/sections.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const db = $derived(data.db);
	const s = section('connect');
</script>

<svelte:head><title>{s.title} · {db.name} — Cryptarch</title></svelte:head>

<PageHeader title={s.title} desc={s.desc} />
{#if db.edge_dirty}<EdgeDirtyAlert />{/if}
<div class="stack-6">
	<div class="card" id="connections">
		{#each db.connections as c, i (i)}
			<div class="conn">
				<span class="conn-label">{c.label}</span>
				<code class="well">{c.conn}</code>
				<CopyButton text={c.conn} label={`Copy ${c.label} connection string`} />
			</div>
		{/each}
	</div>
	<div class="card">
		<SettingRow label="Database and username" desc="The same name for both, by design.">
			<span class="setting-value">{db.name}</span>
		</SettingRow>
		<SettingRow
			label="Password"
			desc="Shown once, when the database was made; only a hash is kept. Lost it? Reset it under Manage, and the old one stops working."
		>
			<span class="setting-value">••••••••</span>
		</SettingRow>
		{#if !db.is_owner}
			<SettingRow label="Owner" desc="You are looking at it as an administrator.">
				<span class="setting-value">{db.owner}</span>
			</SettingRow>
		{/if}
		<SettingRow label="Created" desc={`On ${db.server_name}, a ${db.engine} server.`}>
			<span class="setting-value">{db.created_at.slice(0, 10)}</span>
		</SettingRow>
	</div>
</div>
