<script lang="ts">
	// A database's Manage page: reset the password and delete (CRYPTARCH-143).
	// The reset is the owner's alone and its credential is shown in place, held
	// in this component only (dec D8); delete is armed in its dialog by typing
	// the name, which the server checks again.
	import { onMount, tick } from 'svelte';
	import { api } from '#lib/api.js';
	import ConfirmDialog from './ConfirmDialog.svelte';
	import Credentials, { type Shown } from './Credentials.svelte';
	import SettingRow from './SettingRow.svelte';
	import TypedConfirmDialog from './TypedConfirmDialog.svelte';

	let {
		name,
		status,
		isOwner,
		ondeleted
	}: {
		name: string;
		/** Only an active database's password can be reset; mid-delete or
		 *  mid-restore the role cannot log in (the server refuses too). */
		status: string;
		isOwner: boolean;
		/** Called once the database is gone, with the edge warning if any. */
		ondeleted: (warning: string | null) => void;
	} = $props();
	const path = $derived(`/databases/${encodeURIComponent(name)}`);

	let busy = $state(false);
	let error = $state<string | null>(null);
	let confirmingReset = $state(false);
	let confirmingDelete = $state(false);
	let shown = $state<Shown | null>(null);
	let alertEl = $state<HTMLElement>();

	// The dialog that asked has closed and its opener is disabled while the
	// request runs, so focus would fall to the page: a refusal takes it, so a
	// keyboard or screen-reader user is left on what happened.
	async function fail(e: unknown) {
		error = (e as Error).message;
		busy = false;
		await tick();
		alertEl?.focus();
	}

	// Leaving through a full page load lets the browser keep this page in its
	// back/forward cache, so Back would bring the password back. Forget it as
	// the page is hidden (CRYPTARCH-139).
	onMount(() => {
		const forget = () => (shown = null);
		window.addEventListener('pagehide', forget);
		return () => window.removeEventListener('pagehide', forget);
	});

	async function reset() {
		confirmingReset = false;
		busy = true;
		error = null;
		try {
			shown = await api<Shown>('POST', `${path}/reset`);
			busy = false;
		} catch (e) {
			await fail(e);
		}
	}

	// Armed by the dialog only once the name is typed exactly; the server
	// checks what was typed again. One request however fast it is confirmed.
	async function del(typed: string) {
		if (busy) return;
		confirmingDelete = false;
		busy = true;
		error = null;
		try {
			const r = await api<{ warning: string | null }>('POST', `${path}/delete`, { confirm: typed });
			ondeleted(r.warning);
		} catch (e) {
			await fail(e);
		}
	}
</script>

{#if shown}
	<Credentials heading="New password" {shown} takeFocus />
	<p class="btn-row after-once">
		<button class="btn btn-primary" type="button" onclick={() => (shown = null)}>Done — I've saved it</button>
	</p>
{:else}
	{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
	<div class="stack-6">
		<div class="card">
			<SettingRow
				label="Reset password"
				desc="Generates a new password, shown once. The current one stops working immediately, so anything still using it is cut off."
			>
				{#if isOwner && status !== 'active'}
					<p class="hint">Not while the database is {status}.</p>
				{:else if isOwner}
					<button class="btn" type="button" disabled={busy} onclick={() => (confirmingReset = true)}
						>Reset password</button
					>
				{:else}
					<p class="hint">Only the owner can reset this database's password.</p>
				{/if}
			</SettingRow>
		</div>

		<section class="card card-danger" aria-labelledby="danger-zone">
			<div class="card-head"><h2 id="danger-zone">Danger zone</h2></div>
			<SettingRow
				label="Delete this database"
				desc="Permanent: drops the database and its role on the server. There is no undo. Backups you have already taken are kept, but they become an administrator's: you will not be able to see or restore them."
			>
				<button class="btn btn-danger" type="button" disabled={busy} onclick={() => (confirmingDelete = true)}
					>Delete database…</button
				>
			</SettingRow>
		</section>
	</div>
{/if}

{#if confirmingReset}
	<ConfirmDialog
		title={`Reset the password for ${name}?`}
		message="The current password stops working immediately. The new one is shown once, here."
		action="Reset password"
		onconfirm={reset}
		oncancel={() => (confirmingReset = false)}
	/>
{/if}
{#if confirmingDelete}
	<TypedConfirmDialog
		title={`Delete ${name}?`}
		message="Drops the database and its role on the server; anything connected is cut off. There is no undo. Backups already taken are kept, as an administrator's."
		expected={name}
		action={`Delete ${name}`}
		onconfirm={del}
		oncancel={() => (confirmingDelete = false)}
	/>
{/if}
