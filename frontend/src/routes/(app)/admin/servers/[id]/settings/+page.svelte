<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { resolve } from '$app/paths';
	import ServerSettings from '#lib/components/ServerSettings.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Settings · {data.server.name} · Admin — Cryptarch</title></svelte:head>

{#key data.server.id}
	<ServerSettings server={data.server} onchanged={invalidateAll}
		listenersHref={resolve('/(app)/admin/servers/[id]/listeners', { id: data.server.id })} />
{/key}
