<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import AccessTab from '#lib/components/AccessTab.svelte';
	import EdgeDirtyAlert from '#lib/components/EdgeDirtyAlert.svelte';
	import PageHeader from '#lib/components/PageHeader.svelte';
	import { section } from '#lib/sections.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const db = $derived(data.db);
	const s = section('access');
</script>

<svelte:head><title>{s.title} · {db.name} — Cryptarch</title></svelte:head>

<PageHeader title={s.title} desc={s.desc} />
{#if db.edge_dirty}<EdgeDirtyAlert />{/if}
{#key db.name}
	<AccessTab name={db.name} onchange={invalidateAll} />
{/key}
