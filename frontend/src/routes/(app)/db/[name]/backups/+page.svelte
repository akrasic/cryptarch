<script lang="ts">
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import BackupsTab from '#lib/components/BackupsTab.svelte';
	import PageHeader from '#lib/components/PageHeader.svelte';
	import { section } from '#lib/sections.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const db = $derived(data.db);
	const s = section('backups');
	const job = (id: string) => resolve('/(app)/db/[name]/restores/[id]', { name: db.name, id });
</script>

<svelte:head><title>{s.title} · {db.name} — Cryptarch</title></svelte:head>

<PageHeader title={s.title} desc={s.desc} />
{#key db.name}
	<BackupsTab name={db.name} isOwner={db.is_owner} onrestore={(id) => goto(job(id))} jobHref={job} />
{/key}
