<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import AdminLogins from '#lib/components/AdminLogins.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Login report · Admin — Cryptarch</title></svelte:head>

<AdminLogins report={data.report} onchanged={invalidateAll} />
