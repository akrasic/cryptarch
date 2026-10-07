<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { resolve } from '$app/paths';
	import ServerOverview from '#lib/components/ServerOverview.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Overview · {data.server.name} · Admin — Cryptarch</title></svelte:head>

{#key data.server.id}
	<ServerOverview server={data.server} onchanged={invalidateAll} dbHref={(name) => resolve('/(app)/db/[name]/connect', { name })} />
{/key}
