<script lang="ts">
	// An address that is no page at all, outside the app shell (no sidebar,
	// and perhaps nobody signed in): say so, and offer the way in.
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
</script>

<svelte:head><title>{page.status === 404 ? 'Not found' : 'Something went wrong'} — Cryptarch</title></svelte:head>

<main class="solo">
	<div class="card solo-card">
		<div class="solo-brand"><span class="mark" aria-hidden="true"></span>Cryptarch</div>
		<h1>{page.status === 404 ? 'Not found' : 'Something went wrong'}</h1>
		<p class="solo-tag">
			{page.status === 404 ? 'There is no page at this address.' : (page.error?.message ?? 'An unexpected error occurred.')}
		</p>
		<a class="btn btn-primary btn-block" href={resolve('/(app)/dashboard')}>Go to your databases</a>
	</div>
</main>
