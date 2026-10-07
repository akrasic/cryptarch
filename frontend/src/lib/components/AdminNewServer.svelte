<script lang="ts">
	// Adding a managed server. The DSNs are verified on submit — the admin one
	// must connect and be CREATEDB CREATEROLE, never superuser — and sealed
	// before they are stored. What was typed lives in this component only:
	// kept across a refused submit so it can be corrected, forgotten on
	// pagehide and once the server is added.
	import { onMount, tick } from 'svelte';
	import { api } from '#lib/api.js';
	import PageHeader from './PageHeader.svelte';
	import SettingRow from './SettingRow.svelte';

	let { serversHref, onadded }: { serversHref: string; onadded: (id: string) => void } = $props();

	let name = $state('');
	let adminDsn = $state('');
	let bouncerDsn = $state('');
	let host = $state('');
	let port = $state('');
	let poolMode = $state('session');
	let tlsMode = $state('off');
	let backendKind = $state('docker');
	let defaultCidr = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);
	let alertEl = $state<HTMLParagraphElement | null>(null);

	const forget = () => ([adminDsn, bouncerDsn] = ['', '']);
	onMount(() => {
		window.addEventListener('pagehide', forget);
		return () => window.removeEventListener('pagehide', forget);
	});

	async function submit(ev: SubmitEvent) {
		ev.preventDefault();
		if (busy) return;
		busy = true;
		error = null;
		try {
			const r = await api<{ id: string }>('POST', '/admin/servers', {
				name,
				admin_dsn: adminDsn,
				bouncer_dsn: bouncerDsn.trim() || null,
				host,
				port: Number(port),
				pool_mode: poolMode,
				tls_mode: tlsMode,
				backend_kind: backendKind,
				default_consumer_cidr: defaultCidr.trim() || null
			});
			forget();
			onadded(r.id);
		} catch (e) {
			error = (e as Error).message;
			// The button is at the foot of a long form and the reason is at its
			// head: take the reader to it.
			await tick();
			alertEl?.scrollIntoView?.({ block: 'center' });
			alertEl?.focus();
		} finally {
			busy = false;
		}
	}
</script>

<PageHeader
	title="Add server"
	desc="A database server Cryptarch provisions onto, behind its PgBouncer edge. The admin DSN is checked on submit: it must connect, and its role must be CREATEDB CREATEROLE, never a superuser."
/>
{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
<form class="stack-6" onsubmit={submit}>
	<section class="card" aria-labelledby="conn-h">
		<div class="card-head"><h2 id="conn-h">Connection</h2></div>
		<SettingRow label="Name" desc="How this server appears across the portal. Lowercase letters, digits, - and _.">
			<input class="input mono-text" type="text" name="name" aria-label="Name" placeholder="e.g. pg-shared-1" spellcheck="false" required bind:value={name} />
		</SettingRow>
		<SettingRow label="Admin DSN" desc="Cryptarch's own role on the server. A superuser is refused: CREATEDB CREATEROLE is the ceiling. Stored sealed with the key file.">
			<input class="input mono-text" type="text" name="admin_dsn" aria-label="Admin DSN" placeholder="postgres://cryptarch_admin:…@10.0.0.5:5432/postgres"
				autocomplete="off" spellcheck="false" required bind:value={adminDsn} />
		</SettingRow>
		<SettingRow label="Bouncer console DSN" desc="Lets Cryptarch reload the edge and read pool stats. Optional until server init.">
			<input class="input mono-text" type="text" name="bouncer_dsn" aria-label="Bouncer console DSN" placeholder="postgres://pgbadmin:…@10.0.0.5:6432/pgbouncer"
				autocomplete="off" spellcheck="false" bind:value={bouncerDsn} />
		</SettingRow>
	</section>
	<section class="card" aria-labelledby="edge-h">
		<div class="card-head"><h2 id="edge-h">The edge users connect to</h2></div>
		<SettingRow label="Advertised host" desc="Where users connect: the edge's listener, not Postgres itself.">
			<input class="input mono-text" type="text" name="host" aria-label="Advertised host" placeholder="e.g. 10.0.0.5" spellcheck="false" required bind:value={host} />
		</SettingRow>
		<SettingRow label="Advertised port" desc="The edge listener's port.">
			<input class="input mono-text" type="number" name="port" aria-label="Advertised port" min="1" max="65535" placeholder="6432" required bind:value={port} />
		</SettingRow>
		<SettingRow label="Pool mode" desc="How long a client holds a real Postgres connection. When unsure, keep session: it is fully transparent.">
			<select class="input" name="pool_mode" aria-label="Pool mode" bind:value={poolMode}>
				<option value="session">Session: everything works (default)</option>
				<option value="transaction">Transaction: scales further, breaks session state</option>
			</select>
		</SettingRow>
		<SettingRow label="TLS mode" desc="Whether the edge requires TLS from connecting clients.">
			<select class="input" name="tls_mode" aria-label="TLS mode" bind:value={tlsMode}>
				<option value="off">Off: a trusted network</option>
				<option value="edge">Edge: TLS terminated at the bouncer</option>
			</select>
		</SettingRow>
		<SettingRow label="Backend kind" desc="How the Postgres behind the edge is hosted. Informational for now.">
			<select class="input" name="backend_kind" aria-label="Backend kind" bind:value={backendKind}>
				<option value="docker">Docker</option>
				<option value="vm">VM or bare metal</option>
			</select>
		</SettingRow>
		<SettingRow label={'Default "Allowed from"'} desc="Prefills the access rule when someone provisions a database here. Optional.">
			<input class="input mono-text" type="text" name="default_consumer_cidr" aria-label={'Default "Allowed from"'} placeholder="e.g. 10.10.100.0/24" spellcheck="false" bind:value={defaultCidr} />
		</SettingRow>
		<div class="card-foot">
			<p class="hint">Pool sizes and limits start at sane defaults, adjustable in Settings afterwards.</p>
			<a class="btn btn-quiet" href={serversHref}>Cancel</a>
			<button class="btn btn-primary" type="submit" disabled={busy}>{busy ? 'Verifying…' : 'Verify and add'}</button>
		</div>
	</section>
</form>
