<script lang="ts">
	// A server's Credentials page. An empty field
	// keeps what is stored; a new admin DSN is vetted exactly as when adding a
	// server. Neither DSN is ever shown back — only whether one is stored —
	// and what was typed is forgotten on success and on pagehide.
	import { onMount, tick } from 'svelte';
	import { api } from '#lib/api.js';
	import PageHeader from './PageHeader.svelte';
	import SettingRow from './SettingRow.svelte';

	let {
		serverId,
		hasAdminDsn,
		hasBouncerDsn,
		onchanged
	}: { serverId: string; hasAdminDsn: boolean; hasBouncerDsn: boolean; onchanged: () => Promise<void> } = $props();

	let adminDsn = $state('');
	let bouncerDsn = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	let alertEl = $state<HTMLElement>();
	let noticeEl = $state<HTMLElement>();

	const forget = () => ([adminDsn, bouncerDsn] = ['', '']);
	onMount(() => {
		window.addEventListener('pagehide', forget);
		return () => window.removeEventListener('pagehide', forget);
	});

	async function submit(ev: SubmitEvent) {
		ev.preventDefault();
		if (busy) return;
		busy = true;
		error = notice = null;
		try {
			const r = await api<{ admin: boolean; bouncer: boolean; reconnected: boolean | null }>(
				'POST',
				`/admin/servers/${encodeURIComponent(serverId)}/credentials`,
				{ admin_dsn: adminDsn.trim() || null, bouncer_dsn: bouncerDsn.trim() || null }
			);
			forget();
			// Only what the server confirmed: a reconnect is claimed when it
			// happened, not assumed.
			const admin = !r.admin
				? null
				: r.reconnected === true
					? 'Admin login replaced; Cryptarch reconnected with it.'
					: r.reconnected === false
						? 'Admin login replaced, but Cryptarch could not connect with it — run the connect test.'
						: 'Admin login replaced. The server is disabled; it will be used once the server is enabled.';
			notice = [admin, r.bouncer ? 'Bouncer console login replaced.' : null].filter(Boolean).join(' ');
			await onchanged();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
		// The Save that asked was disabled while this ran: focus goes to the answer.
		await tick();
		(error ? alertEl : noticeEl)?.focus();
	}
</script>

<PageHeader
	title="Credentials"
	desc="The two logins Cryptarch holds for this server, stored sealed with the key file. Neither is ever shown back: only whether one is stored."
/>
{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status" tabindex="-1" bind:this={noticeEl}>{notice}</p>{/if}
<form class="card" onsubmit={submit}>
	<SettingRow
		label="Admin DSN"
		desc={`${hasAdminDsn ? 'Stored (encrypted).' : 'Missing.'} A new one must connect and be CREATEDB CREATEROLE, never a superuser. Empty keeps the current one.`}
	>
		<input class="input mono-text" type="text" name="admin_dsn" aria-label="New admin DSN" autocomplete="off" spellcheck="false" placeholder="keep current" bind:value={adminDsn} />
	</SettingRow>
	<SettingRow
		label="Bouncer console DSN"
		desc={`${hasBouncerDsn ? 'Stored (encrypted).' : 'Not set.'} Lets Cryptarch reload the edge and read pool stats. Empty keeps the current one.`}
	>
		<input class="input mono-text" type="text" name="bouncer_dsn" aria-label="New bouncer console DSN" autocomplete="off" spellcheck="false" placeholder="keep current" bind:value={bouncerDsn} />
	</SettingRow>
	<div class="card-foot">
		<p class="hint">Stored encrypted; never shown again.</p>
		<button class="btn btn-primary" type="submit" disabled={busy}>Save credentials</button>
	</div>
</form>
