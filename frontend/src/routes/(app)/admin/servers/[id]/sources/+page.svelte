<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import ServerSources from '#lib/components/ServerSources.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Sources · {data.server.name} · Admin — Cryptarch</title></svelte:head>

{#key data.server.id}
	<ServerSources serverId={data.server.id} sources={data.config.sources} onchanged={invalidateAll} />
{/key}
