<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import ServerEdge from '#lib/components/ServerEdge.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Edge health · {data.server.name} · Admin — Cryptarch</title></svelte:head>

{#key data.server.id}
	<ServerEdge server={data.server} onchanged={invalidateAll} />
{/key}
