<script lang="ts">
	// Provisioning, and its show-once result. On success the form is
	// replaced by the credentials in place — the password never travels through
	// a URL, a store or a navigation (dec D8).
	import { onMount, untrack } from 'svelte';
	import { resolve } from '$app/paths';
	import { api, ApiError } from '#lib/api.js';
	import Credentials, { type Shown } from '#lib/components/Credentials.svelte';
	import PageHeader from '#lib/components/PageHeader.svelte';
	import SettingRow from '#lib/components/SettingRow.svelte';
	import {
		allowedFromAfterSwitch,
		defaultSourceIds,
		initialAllowedFrom,
		type ServerOption
	} from '#lib/provision.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const servers: ServerOption[] = $derived(data.servers);
	// The form's starting values, read once on purpose: what the user then
	// types must not be reset if the page data reloads.
	const first = untrack(() => data.servers[0]);
	let serverId = $state(first?.id ?? '');
	let name = $state('');
	let allowedFrom = $state(initialAllowedFrom(first));
	let sourceIds = $state<string[]>(defaultSourceIds(first));

	let error = $state<string | null>(null);
	let busy = $state(false);
	let done = $state<(Shown & { warnings: string[] }) | null>(null);

	const selected = $derived(servers.find((s) => s.id === serverId));
	const anySources = $derived(servers.some((s) => s.sources.length > 0));

	// Leaving through a full page load lets the browser keep this page in its
	// back/forward cache, so Back would bring the password back. Forget it as
	// the page is hidden.
	onMount(() => {
		const forget = () => (done = null);
		window.addEventListener('pagehide', forget);
		return () => window.removeEventListener('pagehide', forget);
	});

	function switchServer(next: string) {
		const previous = servers.find((s) => s.id === serverId);
		const target = servers.find((s) => s.id === next);
		allowedFrom = allowedFromAfterSwitch(allowedFrom, previous, target);
		// Only the selected server's sources can be ticked; the others reset.
		sourceIds = defaultSourceIds(target);
		serverId = next;
	}

	function toggleSource(id: string, on: boolean) {
		sourceIds = on ? [...sourceIds, id] : sourceIds.filter((s) => s !== id);
	}

	async function submit(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = null;
		try {
			done = await api('POST', '/databases', {
				server_id: serverId,
				name,
				allowed_from: allowedFrom,
				sources: sourceIds
			});
		} catch (e) {
			error = e instanceof ApiError ? e.message : 'Something went wrong.';
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>{done ? 'Database ready' : 'New database'} — Cryptarch</title></svelte:head>

{#if done}
	<PageHeader
		title="Database ready"
		desc="Its credentials are below. After you leave this page, only a password reset gets you a new one."
	/>
	{#each done.warnings as warning, i (i)}
		<p class="alert alert-warn" role="alert">{warning}</p>
	{/each}
	<Credentials heading="Credentials" level="h2" shown={done} takeFocus />
	<div class="btn-row after-once">
		<a class="btn btn-primary" href={resolve('/(app)/db/[name]/connect', { name: done.name })}>Open the database</a>
		<a class="btn btn-quiet" href={resolve('/(app)/dashboard')}>Back to your databases</a>
	</div>
{:else}
	<PageHeader
		title="New database"
		desc="A database and its own login on a server you choose. Its password is shown once, on the next screen."
	/>
	{#if servers.length === 0}
		<div class="card empty" id="no-servers">
			<h2>Provisioning is unavailable</h2>
			<p>No managed server is configured yet. An administrator adds one under Admin, Servers.</p>
		</div>
	{:else}
		{#if error}
			<p class="alert alert-danger" role="alert">{error}</p>
		{/if}
		<form class="card" onsubmit={submit}>
			<SettingRow label="Server" desc="Where the database lives. Your connection string points at its edge.">
				<select
					class="input"
					name="server_id"
					aria-label="Server"
					required
					value={serverId}
					onchange={(e) => switchServer(e.currentTarget.value)}
				>
					{#each servers as s (s.id)}
						<option value={s.id}>{s.name} ({s.engine})</option>
					{/each}
				</select>
			</SettingRow>
			<SettingRow
				label="Database name"
				desc="Also your username on it. A lowercase letter first, then lowercase letters, digits and underscores; 3–63 characters."
			>
				<input
					class="input mono-text"
					type="text"
					name="name"
					aria-label="Database name"
					placeholder="e.g. alice_app"
					pattern="[a-z][a-z0-9_]{'{'}2,62{'}'}"
					autocomplete="off"
					spellcheck="false"
					required
					bind:value={name}
				/>
			</SettingRow>
			{#if anySources}
				<SettingRow
					label="Allowed sources"
					desc="Where connections may come from: tick what applies. Your admin named these ranges so you don't have to know them."
				>
					<div class="checks">
						{#if !selected || selected.sources.length === 0}
							<p class="hint">No named ranges on this server; use the field below.</p>
						{:else}
							{#each selected.sources as src (src.id)}
								<label class="check">
									<input
										type="checkbox"
										checked={sourceIds.includes(src.id)}
										onchange={(e) => toggleSource(src.id, e.currentTarget.checked)}
									/>
									<span>{src.label} <code>{src.cidr}</code></span>
								</label>
							{/each}
						{/if}
					</div>
				</SettingRow>
			{/if}
			<SettingRow
				label={anySources ? 'Additional sources' : 'Allowed from'}
				desc="Extra IPs or CIDRs, comma-separated, for anything not listed. Empty is fine: the database is still created, and stays unreachable at the edge until a source is allowed."
			>
				<input
					class="input mono-text"
					type="text"
					name="allowed_from"
					aria-label={anySources ? 'Additional sources' : 'Allowed from'}
					placeholder="e.g. 10.10.100.0/24, 10.10.12.33"
					autocomplete="off"
					spellcheck="false"
					bind:value={allowedFrom}
				/>
			</SettingRow>
			<div class="card-foot">
				<p class="hint">The password is shown exactly once, on the next screen.</p>
				<a class="btn btn-quiet" href={resolve('/(app)/dashboard')}>Cancel</a>
				<button class="btn btn-primary" type="submit" disabled={busy}>Provision</button>
			</div>
		</form>
	{/if}
{/if}
