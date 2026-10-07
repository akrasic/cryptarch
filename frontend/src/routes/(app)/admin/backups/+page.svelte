<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { resolve } from '$app/paths';
	import AdminBackups from '#lib/components/AdminBackups.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Backups · Admin — Cryptarch</title></svelte:head>

<AdminBackups
	leftBehind={data.leftBehind}
	unreferenced={data.unreferenced}
	scanError={data.scanError}
	onchanged={invalidateAll}
	dbHref={(name) => resolve('/(app)/db/[name]/backups', { name })}
/>
