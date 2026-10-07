<script lang="ts">
	// An error inside the app: the sidebar stays, so the way out is there too.
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import PageHeader from '#lib/components/PageHeader.svelte';

	const title = $derived(
		page.status === 404 ? 'Not found' : page.status === 403 ? 'Not yours to open' : 'Something went wrong'
	);
</script>

<svelte:head><title>{title} — Cryptarch</title></svelte:head>

<PageHeader {title} desc={page.error?.message ?? 'An unexpected error occurred.'} />
<div class="btn-row"><a class="btn" href={resolve('/(app)/dashboard')}>Back to your databases</a></div>
