<script lang="ts">
	import ServerMaintenance from '#lib/components/ServerMaintenance.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Maintenance · {data.server.name} · Admin — Cryptarch</title></svelte:head>

{#key data.server.id}
	<ServerMaintenance serverId={data.server.id} />
{/key}
