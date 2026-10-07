<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import Profile from '#lib/components/Profile.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Profile — Cryptarch</title></svelte:head>

<Profile me={data.me} onchanged={invalidateAll} />
