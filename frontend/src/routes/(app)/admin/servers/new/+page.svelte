<script lang="ts">
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import AdminNewServer from '#lib/components/AdminNewServer.svelte';
</script>

<svelte:head><title>Add server · Admin — Cryptarch</title></svelte:head>

<AdminNewServer
	serversHref={resolve('/(app)/admin/servers')}
	onadded={(id) => goto(resolve('/(app)/admin/servers/[id]/overview', { id }))}
/>
