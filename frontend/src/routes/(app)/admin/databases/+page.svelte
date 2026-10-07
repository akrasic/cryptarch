<script lang="ts">
	import { resolve } from '$app/paths';
	import AdminDatabases from '#lib/components/AdminDatabases.svelte';
	import { takeNotice } from '#lib/notice.svelte.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	// Left by a delete that landed here; shown once.
	const notice = takeNotice();
</script>

<svelte:head><title>All databases · Admin — Cryptarch</title></svelte:head>

<AdminDatabases databases={data.databases} dbHref={(name) => resolve('/(app)/db/[name]/connect', { name })}>
	{#if notice?.warning}<p class="alert alert-warn" role="alert">{notice.warning}</p>{/if}
	{#if notice}<p class="alert alert-ok" role="status">{notice.message}</p>{/if}
</AdminDatabases>
