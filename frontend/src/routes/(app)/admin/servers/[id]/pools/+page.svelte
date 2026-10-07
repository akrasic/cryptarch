<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import ServerPools from '#lib/components/ServerPools.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Pools · {data.server.name} · Admin — Cryptarch</title></svelte:head>

{#key data.server.id}
	<ServerPools serverId={data.server.id} poolMode={data.server.pool_mode} maxUserConnections={data.server.max_user_connections}
		databases={data.config.databases} onchanged={invalidateAll} />
{/key}
