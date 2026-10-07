<script lang="ts">
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { afterDelete } from '#lib/after-delete.js';
	import ManageTab from '#lib/components/ManageTab.svelte';
	import PageHeader from '#lib/components/PageHeader.svelte';
	import { section } from '#lib/sections.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const db = $derived(data.db);
	const s = section('manage');

	function deleted(warning: string | null) {
		goto(afterDelete(data.me.is_admin, warning, resolve('/(app)/dashboard'), resolve('/(app)/admin/databases')));
	}
</script>

<svelte:head><title>{s.title} · {db.name} — Cryptarch</title></svelte:head>

<PageHeader title={s.title} desc={s.desc} />
{#key db.name}
	<ManageTab name={db.name} status={db.status} isOwner={db.is_owner} ondeleted={deleted} />
{/key}
