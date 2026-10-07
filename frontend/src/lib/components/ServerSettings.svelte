<script lang="ts">
	// A server's Settings page: three cards (Credentials has its own page). Each
	// saves on its own; pooling and edge push to the edge and say whether it
	// took the change.
	import { tick, untrack } from 'svelte';
	import { api } from '#lib/api.js';
	import { edgeNote, type EdgeOutcome, type Server } from '#lib/admin-servers.js';
	import PageHeader from './PageHeader.svelte';
	import SettingRow from './SettingRow.svelte';

	let {
		server,
		onchanged,
		listenersHref
	}: { server: Server; onchanged: () => Promise<void>; listenersHref: string } = $props();

	const base = $derived(`/admin/servers/${encodeURIComponent(server.id)}/settings`);
	// Seeded once from the row. A save reloads the row, and re-seeding then
	// would wipe what is typed, unsaved, in the other cards; a different
	// server remounts this ({#key} in the route).
	let host = $state('');
	let port = $state('');
	let poolMode = $state('');
	let poolSize = $state('');
	let clientConn = $state('');
	let dbConns = $state('');
	let userConns = $state('');
	let tlsMode = $state('');
	let backendKind = $state('');
	let cidr = $state('');
	let confDir = $state('');
	untrack(() => {
		host = server.host;
		port = String(server.port);
		poolMode = server.pool_mode;
		poolSize = String(server.default_pool_size);
		clientConn = String(server.max_client_conn);
		dbConns = String(server.max_db_connections);
		userConns = String(server.max_user_connections);
		tlsMode = server.tls_mode;
		backendKind = server.backend_kind;
		cidr = server.default_consumer_cidr ?? '';
		confDir = server.bouncer_conf_dir ?? '';
	});

	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	let alertEl = $state<HTMLElement>();
	let noticeEl = $state<HTMLElement>();

	async function save(ev: SubmitEvent, path: string, body: unknown, what: string) {
		ev.preventDefault();
		if (busy) return;
		busy = true;
		error = notice = null;
		try {
			const r = await api<{ edge?: EdgeOutcome; reconnected?: boolean | null }>('POST', `${base}/${path}`, body);
			if (r.edge) {
				const n = edgeNote(what, r.edge);
				if (n.failed) error = n.text;
				else notice = n.text;
			} else if (r.reconnected === false) {
				error = `${what}, but Cryptarch could not reconnect to the server — run the connect test.`;
			} else {
				notice = `${what}.`;
			}
			await onchanged();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
		// The Save that asked was disabled while this ran: focus goes to the
		// answer, at the top, rather than to the page.
		await tick();
		(error ? alertEl : noticeEl)?.focus();
	}
</script>

<PageHeader title="Settings" desc="Where users connect, how the edge pools connections, and how it is configured. Each card saves on its own." />
{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status" tabindex="-1" bind:this={noticeEl}>{notice}</p>{/if}

<div class="stack-6">
	<form class="card" id="address-form" aria-labelledby="address-h"
		onsubmit={(ev) => save(ev, 'address', { host, port: Number(port) }, 'Address saved')}>
		<div class="card-head"><h2 id="address-h">Advertised address</h2></div>
		<SettingRow label="Host" desc="Where users connect: the edge's listener, not Postgres itself. An IP or a name your users can reach.">
			<input class="input mono-text" type="text" name="host" aria-label="Host" spellcheck="false" required bind:value={host} />
		</SettingRow>
		<SettingRow label="Port" desc="The edge listener's port.">
			<input class="input mono-text" type="number" name="port" aria-label="Port" min="1" max="65535" required bind:value={port} />
		</SettingRow>
		<div class="card-foot">
			<p class="hint">Lands in every new connection string. Extra addresses are under <a href={listenersHref}>Listeners</a>.</p>
			<button class="btn btn-primary" type="submit" disabled={busy}>Save</button>
		</div>
	</form>

	<form class="card" id="pooling-form" aria-labelledby="pooling-h"
		onsubmit={(ev) => save(ev, 'pooling', {
			pool_mode: poolMode, default_pool_size: Number(poolSize), max_client_conn: Number(clientConn),
			max_db_connections: Number(dbConns), max_user_connections: Number(userConns)
		}, 'Pooling saved')}>
		<div class="card-head"><h2 id="pooling-h">Connection pooling</h2></div>
		<SettingRow label="Pool mode"
			desc="How long a client holds a real connection. Session: for its whole stay; everything works, and idle clients occupy a slot. Transaction: only while a transaction runs; serves far more clients, but breaks LISTEN/NOTIFY, session variables and friends. When unsure, keep session.">
			<select class="input" name="pool_mode" aria-label="Pool mode" bind:value={poolMode}>
				<option value="session">Session: everything works (default)</option>
				<option value="transaction">Transaction: scales further, breaks session state</option>
			</select>
		</SettingRow>
		<SettingRow label="Default pool size" desc="Real Postgres connections each database's pool keeps open. Per-database overrides are under Pools.">
			<div class="unit"><input class="input mono-text" type="number" name="default_pool_size" aria-label="Default pool size" min="1" max="1000" required bind:value={poolSize} /><span>connections</span></div>
		</SettingRow>
		<SettingRow label="Max client connections" desc="App connections the edge accepts in total, across all databases.">
			<div class="unit"><input class="input mono-text" type="number" name="max_client_conn" aria-label="Max client connections" min="1" max="10000" required bind:value={clientConn} /><span>clients</span></div>
		</SettingRow>
		<SettingRow label="Max per database" desc="Ceiling on real Postgres connections one database may use. 0 means unlimited.">
			<div class="unit"><input class="input mono-text" type="number" name="max_db_connections" aria-label="Max per database" min="0" max="10000" required bind:value={dbConns} /><span>connections</span></div>
		</SettingRow>
		<SettingRow label="Max per user" desc="Ceiling on real Postgres connections one user may hold. 0 means unlimited.">
			<div class="unit"><input class="input mono-text" type="number" name="max_user_connections" aria-label="Max per user" min="0" max="10000" required bind:value={userConns} /><span>connections</span></div>
		</SettingRow>
		<div class="card-foot">
			<p class="hint">Applied to the edge immediately on save.</p>
			<button class="btn btn-primary" type="submit" disabled={busy}>Save</button>
		</div>
	</form>

	<form class="card" id="edge-form" aria-labelledby="edge-h"
		onsubmit={(ev) => save(ev, 'edge', {
			tls_mode: tlsMode, backend_kind: backendKind,
			default_consumer_cidr: cidr.trim() || null, bouncer_conf_dir: confDir.trim() || null
		}, 'Edge settings saved')}>
		<div class="card-head"><h2 id="edge-h">Edge and access</h2></div>
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
		<SettingRow label={'Default "Allowed from"'} desc="Prefills the access rule when someone provisions a database here. A tenant may allow it even when wider than /16, unless it reaches 0.0.0.0 or ::, which only an admin can allow.">
			<input class="input mono-text" type="text" name="default_consumer_cidr" aria-label={'Default "Allowed from"'} placeholder="e.g. 10.10.100.0/24" spellcheck="false" bind:value={cidr} />
		</SettingRow>
		<SettingRow label="Bouncer conf dir"
			desc="A local path, holding pgbouncer.ini, that Cryptarch writes edge config into. Empty means config is rendered for you to place instead.">
			<input class="input mono-text" type="text" name="bouncer_conf_dir" aria-label="Bouncer conf dir" placeholder="e.g. /etc/pgbouncer" spellcheck="false" bind:value={confDir} />
		</SettingRow>
		<div class="card-foot">
			<p class="hint">TLS and conf dir changes re-sync the edge.</p>
			<button class="btn btn-primary" type="submit" disabled={busy}>Save</button>
		</div>
	</form>
</div>
