<script lang="ts">
	// Signing in (the design system's sign-in card). The messages are the API's own.
	import { onMount, tick } from 'svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { api, ApiError } from '#lib/api.js';

	let username = $state('');
	let password = $state('');
	let error = $state<string | null>(null);
	let busy = $state(false);
	let alertEl = $state<HTMLElement>();
	// A typed, unsubmitted password never goes into the back/forward cache.
	onMount(() => {
		const forget = () => (password = '');
		window.addEventListener('pagehide', forget);
		return () => window.removeEventListener('pagehide', forget);
	});

	async function submit(event: SubmitEvent) {
		event.preventDefault();
		// Enter pressed again while the first answer is on its way sends nothing.
		if (busy) return;
		busy = true;
		error = null;
		try {
			await api('POST', '/session', { username, password });
			await goto(resolve('/(app)/dashboard'));
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong.';
			password = '';
			busy = false;
			// The refusal takes focus: Sign in was disabled while it was asked.
			await tick();
			alertEl?.focus();
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>Sign in — Cryptarch</title></svelte:head>

<main class="solo">
	<div class="card solo-card">
		<div class="solo-brand"><span class="mark" aria-hidden="true"></span>Cryptarch</div>
		<h1>Sign in</h1>
		<p class="solo-tag">Provision a database. Get the keys once.</p>
		{#if error}
			<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>
		{/if}
		<form class="solo-form" onsubmit={submit}>
			<label class="field">
				<span>Username</span>
				<!-- svelte-ignore a11y_autofocus — it is the only field that matters here -->
				<input class="input" type="text" name="username" autocomplete="username" spellcheck="false" autofocus required bind:value={username} />
			</label>
			<label class="field">
				<span>Password</span>
				<input class="input" type="password" name="password" autocomplete="current-password" required bind:value={password} />
			</label>
			<button class="btn btn-primary btn-block" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
		</form>
	</div>
</main>
