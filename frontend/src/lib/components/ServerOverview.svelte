<script lang="ts">
	// A server's Overview: what it is, the things you do to it (init, the
	// connect test, enable/disable), and the databases on it as the server
	// itself reports them. The server's own answer is fetched after the row
	// is on screen, because it can take seconds on a bad day.
	import { onMount, tick } from 'svelte';
	import { api } from '#lib/api.js';
	import type { Overview, Server, TestReport } from '#lib/admin-servers.js';
	import { humanBytes } from '#lib/format.js';
	import AdminServerInit, { type InitReport } from './AdminServerInit.svelte';
	import ConfirmDialog from './ConfirmDialog.svelte';
	import PageHeader from './PageHeader.svelte';
	import SettingRow from './SettingRow.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let {
		server,
		onchanged,
		dbHref
	}: {
		server: Server;
		onchanged: () => Promise<void>;
		dbHref: (name: string) => string;
	} = $props();
	const base = $derived(`/admin/servers/${encodeURIComponent(server.id)}`);

	let overview = $state<Overview | null>(null);
	let overviewError = $state<string | null>(null);
	let report = $state<TestReport | null>(null);
	let initReport = $state<InitReport | null>(null);
	let confirming = $state(false);
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	let alertEl = $state<HTMLElement>();
	let noticeEl = $state<HTMLElement>();

	// Each ask carries its turn: a slow answer from before an enable or
	// disable must not paint over the one asked for after it.
	let overviewTurn = 0;
	async function loadOverview() {
		const mine = ++overviewTurn;
		try {
			const o = await api<Overview>('GET', `${base}/overview`);
			if (mine === overviewTurn) [overview, overviewError] = [o, null];
		} catch (e) {
			if (mine === overviewTurn) overviewError = (e as Error).message;
		}
	}
	onMount(() => {
		loadOverview();
	});

	// The button that asked was disabled while the request ran, so focus goes
	// to what happened rather than to the page.
	async function land(answer?: () => HTMLElement | undefined) {
		await tick();
		(error ? alertEl : (answer?.() ?? noticeEl))?.focus();
	}
	let reportEl = $state<HTMLElement>();
	let initEl = $state<HTMLElement>();

	async function runTest() {
		if (busy) return;
		busy = true;
		error = notice = null;
		report = null;
		try {
			report = await api<TestReport>('POST', `${base}/test`);
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
		await land(() => reportEl);
	}

	async function runInit() {
		if (busy) return;
		busy = true;
		error = notice = null;
		initReport = null;
		try {
			initReport = await api<InitReport>('POST', `${base}/init`);
			// Its init status changed, whatever the outcome.
			await onchanged();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
		await land(() => initEl);
	}

	async function setActive(active: boolean) {
		confirming = false;
		if (busy) return;
		busy = true;
		error = notice = null;
		try {
			const r = await api<{ active: boolean; connected: boolean | null }>('POST', `${base}/active`, { active });
			// What it is now, which a concurrent change may have decided.
			notice = !r.active
				? `${server.name} is disabled. Provisioning onto it stops until it is enabled again.`
				: r.connected
					? `${server.name} is enabled and connected.`
					: `${server.name} is enabled, but Cryptarch could not connect to it. Run the connect test to see why.`;
			await onchanged();
			// A different engine answers now, or none does.
			overview = null;
			loadOverview();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
		await land();
	}
</script>

<PageHeader title="Overview" desc="What this server is, the checks you can run on it, and the databases it holds.">
	{#snippet actions()}
		<button class="btn" type="button" disabled={busy} onclick={runTest}>Run connect test</button>
		<button class="btn" type="button" disabled={busy} onclick={runInit}>Run server init</button>
	{/snippet}
</PageHeader>
{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status" tabindex="-1" bind:this={noticeEl}>{notice}</p>{/if}

<div class="stack-6">
	{#if initReport}
		<div tabindex="-1" bind:this={initEl}><AdminServerInit report={initReport} ondone={() => (initReport = null)} /></div>
	{/if}

	{#if report}
		<section class="card" aria-labelledby="connect-test-h" tabindex="-1" bind:this={reportEl}>
			<div class="card-head"><h2 id="connect-test-h">Connect test</h2></div>
			<div class="table-wrap">
				<table class="table" id="connect-test">
					<tbody>
						{#each report.checks as c (c.check)}
							<tr>
								<td>{c.check}</td>
								<td><span class={c.ok ? 'badge badge-ok badge-wrap' : 'badge badge-danger badge-wrap'}>{c.detail}</span></td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>
	{/if}

	<div class="card" id="server-facts">
		<SettingRow label="Status" desc="Whether Cryptarch provisions onto it, and whether it answered.">
			<StatusBadge status={server.status} />
		</SettingRow>
		<SettingRow label="Engine" desc="The database engine behind the edge.">
			<span class="setting-value">{server.engine}</span>
		</SettingRow>
		<SettingRow label="Databases" desc="Databases Cryptarch manages here.">
			<span class="setting-value">{server.db_count}</span>
		</SettingRow>
		<SettingRow label="Admin DSN" desc="Cryptarch's own login on the server. Replace it under Credentials.">
			{#if server.has_admin_dsn}
				<span class="setting-value">Stored (encrypted)</span>
			{:else}
				<span class="badge badge-danger">Missing</span>
			{/if}
		</SettingRow>
		<SettingRow label="Bouncer DSN" desc="Lets Cryptarch reload the edge and read pool stats.">
			{#if server.has_bouncer_dsn}
				<span class="setting-value">Stored (encrypted)</span>
			{:else}
				<span class="badge">Not set</span>
			{/if}
		</SettingRow>
		<SettingRow label="Init" desc="Whether the server holds the roles and functions the edge's authentication needs.">
			{#if server.init_status === 'ready'}
				<StatusBadge status="ready" />
			{:else if server.init_status === 'pending'}
				<span class="badge badge-unknown">Pending: run server init</span>
			{:else if server.init_status === 'needs_bootstrap'}
				<span class="badge badge-warn">Needs superuser bootstrap</span>
			{:else}
				<StatusBadge status="failed" />
			{/if}
		</SettingRow>
		<SettingRow label="Conf dir" desc="Where Cryptarch writes edge config. Without one, it is rendered for you to place.">
			{#if server.bouncer_conf_dir}
				<span class="setting-value">{server.bouncer_conf_dir}</span>
			{:else}
				<span class="badge">Not set: manual placement</span>
			{/if}
		</SettingRow>
		<SettingRow
			label={server.is_active ? 'Disable server' : 'Enable server'}
			desc={server.is_active
				? 'Stops provisioning onto it, and Cryptarch lets go of it: its databases keep serving connections, but their owners cannot reset, delete, back up or restore them, and health checks stop, until it is enabled again.'
				: 'Lets Cryptarch use it again: provisioning, resets, deletes, backups and health checks, once it can connect.'}
		>
			{#if server.is_active}
				<button class="btn btn-danger" type="button" disabled={busy} onclick={() => (confirming = true)}>Disable…</button>
			{:else}
				<button class="btn" type="button" disabled={busy} onclick={() => setActive(true)}>Enable</button>
			{/if}
		</SettingRow>
	</div>

	<div>
		<h2 class="section-title first">On this server</h2>
		{#if overviewError}
			<p class="alert alert-danger" role="alert">{overviewError}</p>
		{:else if !overview}
			<p class="loading">Asking the server…</p>
		{:else if !overview.dashboard}
			<div class="card empty empty-blind" id="dashboard-unavailable">
				<h3>Server dashboard unavailable</h3>
				<p>The managed server did not respond, or is not connected. Refresh to try again.</p>
			</div>
		{:else}
			{@const o = overview.dashboard}
			<div class="stats">
				<div class="card stat"><span class="stat-n">{o.version.split(/\s+/)[0]}</span><span class="stat-l">PostgreSQL</span></div>
				<div class="card stat"><span class="stat-n">{o.uptime}</span><span class="stat-l">Up for</span></div>
				<div class="card stat">
					<span class="stat-n">{o.total_connections} / {o.max_connections}</span><span class="stat-l">Connections</span>
				</div>
			</div>
			{@const managed = o.databases.filter((d) => d.managed)}
			{@const external = o.databases.filter((d) => !d.managed)}
			{#if managed.length === 0 && server.db_count > 0}
				<!-- Cryptarch holds databases here but none was matched: its own list
				     could not be read, which is not "manages none". -->
				<div class="card empty empty-blind" id="managed-unknown">
					<h3>Cryptarch's databases here could not be matched</h3>
					<p>It manages {server.db_count} on this server, but could not tell which of the databases on it they are. Refresh to try again.</p>
				</div>
			{:else if managed.length === 0}
				<div class="card empty" id="no-managed">
					<h3>Cryptarch manages none here yet</h3>
					<p>Databases provisioned onto this server will be listed here.</p>
				</div>
			{:else}
				<div class="card table-wrap">
					<table class="table" id="server-dbs">
						<thead><tr><th>Database</th><th class="num">Size</th><th class="num">Connections</th></tr></thead>
						<tbody>
							{#each managed as d (d.name)}
								<tr>
									<td><a class="row-link" href={dbHref(d.name)}>{d.name}</a></td>
									<td class="num">{humanBytes(d.size_bytes)}</td>
									<td class="num">{d.connections}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
			{#if external.length > 0}
				<!-- Shown, because they share the server's connections and disk;
				     folded, because they are not Cryptarch's to manage. -->
				<details class="card fold" id="external-dbs">
					<summary>
						{external.length} other database{external.length === 1 ? '' : 's'} on this server, not Cryptarch's
					</summary>
					<div class="table-wrap">
						<table class="table">
							<thead><tr><th>Database</th><th class="num">Size</th><th class="num">Connections</th></tr></thead>
							<tbody>
								{#each external as d (d.name)}
									<tr>
										<td><code>{d.name}</code></td>
										<td class="num">{humanBytes(d.size_bytes)}</td>
										<td class="num">{d.connections}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				</details>
			{/if}
		{/if}
	</div>
</div>

{#if confirming}
	<ConfirmDialog
		title={`Disable ${server.name}?`}
		message="Its databases keep serving connections, but until it is enabled again nothing can be provisioned onto it, and their owners cannot reset, delete, back up or restore them. Scheduled backups and health checks stop too."
		action="Disable"
		onconfirm={() => setActive(false)}
		oncancel={() => (confirming = false)}
	/>
{/if}
