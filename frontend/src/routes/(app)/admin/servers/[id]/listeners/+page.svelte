<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import ServerListeners from '#lib/components/ServerListeners.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Listeners · {data.server.name} · Admin — Cryptarch</title></svelte:head>

{#key data.server.id}
	<ServerListeners serverId={data.server.id} primary={`${data.server.host}:${data.server.port}`}
		listeners={data.config.listeners} onchanged={invalidateAll} />
{/key}
