<script lang="ts">
	// One restore, at its own address: something you can return to, refresh
	// and send to someone while it runs (CRYPTARCH-95). The sidebar keeps
	// Backups marked, the section it belongs to.
	import PageHeader from '#lib/components/PageHeader.svelte';
	import RestoreJob from '#lib/components/RestoreJob.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Restore · {data.name} — Cryptarch</title></svelte:head>

<PageHeader
	title="Restore"
	desc="Replacing this database with the contents of a backup, step by step. Until the last step commits, the database holds exactly what it held before."
/>
{#key data.job.id}
	<RestoreJob name={data.name} initial={data.job} />
{/key}
