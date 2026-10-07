<script lang="ts">
	// A database's Access page: the edge ACL, its quick-adds and the allow
	// form (CRYPTARCH-142). One instance per
	// database — the page keys it by name, so nothing here can outlive a
	// navigation to another database.
	import { onMount } from 'svelte';
	import { api } from '#lib/api.js';
	import ConfirmDialog from './ConfirmDialog.svelte';
	import SettingRow from './SettingRow.svelte';

	interface AclEntry {
		id: string;
		cidr: string;
		created_by: string;
		note: string | null;
	}
	interface Acl {
		entries: AclEntry[];
		unallowed_sources: { id: string; label: string; cidr: string }[];
	}

	let { name, onchange }: { name: string; onchange: () => Promise<void> } = $props();
	const path = $derived(`/databases/${encodeURIComponent(name)}/acl`);

	// Re-read from the server after every change — what it shows is what the
	// edge is rendered from, not a local guess. The last list stays on screen
	// while that happens, so the table and form don't blink out.
	let acl = $state<Acl | null>(null);
	let loadError = $state<string | null>(null);
	async function load() {
		try {
			[acl, loadError] = [await api<Acl>('GET', path), null];
		} catch (e) {
			loadError = (e as Error).message;
		}
	}
	onMount(load);

	let cidr = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	// The edge did not take the change; it stays until the next change.
	let warning = $state<string | null>(null);
	let removing = $state<AclEntry | null>(null);

	async function change(run: () => Promise<{ warning: string | null; done: string }>) {
		busy = true;
		error = notice = warning = null;
		try {
			const r = await run();
			[notice, warning] = [r.done, r.warning];
			return true;
		} catch (e) {
			error = (e as Error).message;
			return false;
		} finally {
			// The list, and whatever else the page shows about the edge (its
			// out-of-sync banner). Controls stay disabled until both are current.
			await Promise.all([load(), onchange()]);
			busy = false;
		}
	}

	async function allow(value: string, note?: string) {
		const ok = await change(async () => {
			const r = await api<{ created: boolean; warning: string | null }>(
				'POST',
				path,
				note === undefined ? { cidr: value } : { cidr: value, note }
			);
			// 200 means it was already there: nothing was added, and the note
			// sent with it was not kept.
			return { warning: r.warning, done: r.created ? 'Source allowed.' : 'Already allowed — nothing changed.' };
		});
		if (ok && note === undefined) cidr = '';
	}

	async function remove(entry: AclEntry) {
		removing = null;
		await change(async () => {
			const r = await api<{ warning: string | null }>('DELETE', `${path}/${encodeURIComponent(entry.id)}`);
			return { warning: r.warning, done: 'Source removed.' };
		});
	}
</script>

{#if error}<p class="alert alert-danger" role="alert">{error}</p>{/if}
{#if warning}<p class="alert alert-warn" role="alert">{warning}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status">{notice}</p>{/if}
{#if loadError}
	<p class="alert alert-danger" role="alert">{loadError}</p>
{:else if !acl}
	<p class="loading">Loading…</p>
{:else}
	{@const a = acl}
	<div class="stack-6">
		{#if a.entries.length === 0}
			<div class="card empty" id="acl-empty">
				<h2>Nothing can connect</h2>
				<p>No network is allowed, so the bouncer refuses every connection to this database. Allow one below.</p>
			</div>
		{:else}
			<div class="card table-wrap">
				<table class="table" id="acl">
					<thead><tr><th>Allowed from</th><th>Added by</th><th><span class="sr-only">Actions</span></th></tr></thead>
					<tbody>
						{#each a.entries as e (e.id)}
							<tr>
								<td>
									<code>{e.cidr}</code>
									{#if e.note}<span class="sub">{e.note}</span>{/if}
								</td>
								<td class="sub">{e.created_by}</td>
								<td class="act">
									<button
										class="btn btn-quiet btn-sm"
										type="button"
										disabled={busy}
										aria-label={`Remove source ${e.cidr}`}
										onclick={() => (removing = e)}>Remove</button
									>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
		<form
			class="card"
			onsubmit={(ev) => {
				ev.preventDefault();
				allow(cidr);
			}}
		>
			{#if a.unallowed_sources.length > 0}
				<SettingRow
					label="Quick add"
					desc="Ranges your admin has named on this server, one click to allow."
				>
					{#each a.unallowed_sources as src (src.id)}
						<button
							class="btn btn-sm"
							type="button"
							disabled={busy}
							aria-label={`Allow ${src.label} (${src.cidr})`}
							onclick={() => allow(src.cidr, src.label)}
							>+ {src.label} <code>{src.cidr}</code></button
						>
					{/each}
				</SettingRow>
			{/if}
			<SettingRow
				label="Allow a source"
				desc="An IP or CIDR to admit at the edge: 10.10.100.0/24, or a single address. Your own ranges can be /16 or narrower; wider ones are an admin's to name."
			>
				<input
					class="input mono-text"
					type="text"
					name="cidr"
					placeholder="10.10.100.0/24"
					autocomplete="off"
					spellcheck="false"
					aria-label="Source to allow"
					required
					bind:value={cidr}
				/>
			</SettingRow>
			<div class="card-foot">
				<p class="hint">Applied to the edge immediately.</p>
				<button class="btn btn-primary" type="submit" disabled={busy}>Allow source</button>
			</div>
		</form>
	</div>
{/if}
{#if removing}
	{@const r = removing}
	<ConfirmDialog
		title={`Remove ${r.cidr}?`}
		message="Clients there lose access at the edge immediately."
		action="Remove"
		onconfirm={() => remove(r)}
		oncancel={() => (removing = null)}
	/>
{/if}
