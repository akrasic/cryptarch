<script lang="ts">
	import { resolve } from '$app/paths';
	import AdminServers from '#lib/components/AdminServers.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Servers · Admin — Cryptarch</title></svelte:head>

<AdminServers
	servers={data.servers}
	serverHref={(id) => resolve('/(app)/admin/servers/[id]/overview', { id })}
	settingsHref={(id) => resolve('/(app)/admin/servers/[id]/settings', { id })}
	addHref={resolve('/(app)/admin/servers/new')}
/>
