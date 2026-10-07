<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { resolve } from '$app/paths';
	import AdminUserDetail from '#lib/components/AdminUserDetail.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>{data.detail.user.username} · Admin — Cryptarch</title></svelte:head>

{#key data.detail.user.id}
	<AdminUserDetail
		user={data.detail.user}
		isSelf={data.detail.is_self}
		databases={data.detail.databases}
		onchanged={invalidateAll}
		profileHref={resolve('/(app)/profile')}
		dbHref={(name) => resolve('/(app)/db/[name]/connect', { name })}
	/>
{/key}
