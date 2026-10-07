<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import AdminServerCredentials from '#lib/components/AdminServerCredentials.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Credentials · {data.server.name} · Admin — Cryptarch</title></svelte:head>

{#key data.server.id}
	<AdminServerCredentials serverId={data.server.id} hasAdminDsn={data.server.has_admin_dsn}
		hasBouncerDsn={data.server.has_bouncer_dsn} onchanged={invalidateAll} />
{/key}
