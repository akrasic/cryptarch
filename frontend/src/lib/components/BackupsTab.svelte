<script lang="ts">
	// A database's Backups page: start a backup, and the history, which follows itself while a job runs
	// (CRYPTARCH-144; lib/poll). Starting one is the owner's; an admin viewing
	// someone else's database sees the history only. Restores (CRYPTARCH-145):
	// the owner's, from a finished backup, armed by typing the name; the
	// restore history below follows a running one, and each job has a page.
	import { onMount, tick } from 'svelte';
	import { api, ApiError } from '#lib/api.js';
	import { humanBytes } from '#lib/format.js';
	import { poll, type Poller } from '#lib/poll.js';
	import SettingRow from './SettingRow.svelte';
	import StatusBadge from './StatusBadge.svelte';
	import TypedConfirmDialog from './TypedConfirmDialog.svelte';

	interface Backup {
		id: string;
		created_at: string;
		finished_at: string | null;
		size_bytes: number | null;
		took: string;
		status: string;
		error: string | null;
		log: string;
		verified: boolean;
		contents: { state: 'unknown' | 'needs_care' | 'recorded'; detail: string | null };
	}
	interface Backups {
		enabled: boolean;
		backups: Backup[];
	}
	interface RestoreSummary {
		id: string;
		created_at: string;
		status: string;
		requested_by: string;
		stage_title: string | null;
	}

	let {
		name,
		isOwner,
		onrestore,
		jobHref
	}: {
		name: string;
		isOwner: boolean;
		/** A restore was started: go to its job page. */
		onrestore: (id: string) => void;
		/** Where a restore job's page is. */
		jobHref: (id: string) => string;
	} = $props();
	const path = $derived(`/databases/${encodeURIComponent(name)}/backups`);
	const restoresPath = $derived(`/databases/${encodeURIComponent(name)}/restores`);

	let restores = $state<RestoreSummary[]>([]);
	let restoring = $state<Backup | null>(null);
	let restoreError = $state<string | null>(null);
	let restoreAlert = $state<HTMLElement>();

	let data = $state<Backups | null>(null);
	let loadError = $state<string | null>(null);
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	let poller: Poller | null = null;
	let restorePoller: Poller | null = null;

	onMount(() => {
		// Only shown once there is one; followed while one runs.
		restorePoller = poll<{ restores: RestoreSummary[] }>({
			fetch: () => api('GET', restoresPath),
			running: (r) => r.restores.some((x) => x.status === 'running'),
			intervalMs: 2000,
			onValue: (r) => (restores = r.restores),
			onError: (e) => {
				if (e instanceof ApiError && [401, 403, 404].includes(e.status)) restorePoller?.stop();
			}
		});
		poller = poll<Backups>({
			fetch: () => api<Backups>('GET', path),
			running: (b) => b.backups.some((x) => x.status === 'running'),
			onValue: (b) => ([data, loadError] = [b, null]),
			onError: (e) => {
				loadError = (e as Error).message;
				// Signed out, or the database is gone: asking again every few
				// seconds will not change the answer.
				if (e instanceof ApiError && [401, 403, 404].includes(e.status)) poller?.stop();
			}
		});
		return () => {
			poller?.stop();
			restorePoller?.stop();
		};
	});

	async function restore(b: Backup, typed: string) {
		restoring = null;
		busy = true;
		restoreError = null;
		try {
			const r = await api<{ id: string }>('POST', restoresPath, { backup_id: b.id, confirm: typed });
			onrestore(r.id);
		} catch (e) {
			// The dialog has closed and the row's button is disabled while this
			// ran: the refusal takes focus, rather than the page.
			restoreError = (e as Error).message;
			busy = false;
			await tick();
			restoreAlert?.focus();
		} finally {
			busy = false;
		}
	}

	async function start() {
		busy = true;
		error = notice = null;
		try {
			await api('POST', path);
			notice = 'Backup started.';
			// Follow it: the history now has a running row.
			poller?.kick();
		} catch (e) {
			error = (e as Error).message;
			// One is running that this page has not shown yet (the scheduler,
			// another tab): show it.
			if (e instanceof ApiError && e.code === 'already_running') poller?.kick();
		} finally {
			busy = false;
		}
	}

	// "%Y-%m-%d %H:%M UTC", as the server words times.
	const taken = (iso: string) => iso.slice(0, 16).replace('T', ' ') + ' UTC';
</script>

{#if loadError}
	<p class="alert alert-danger" role="alert">{loadError}</p>
{/if}
{#if !data}
	{#if !loadError}<p class="loading">Loading…</p>{/if}
{:else if !data.enabled}
	<div class="card empty" id="backups-off">
		<h2>Backups are off on this deployment</h2>
		<p>An administrator turns them on by giving Cryptarch a backup directory.</p>
	</div>
{:else}
	{#if error}<p class="alert alert-danger" role="alert">{error}</p>{/if}
	{#if notice}<p class="alert alert-progress" role="status">{notice}</p>{/if}
	{#if restoreError}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={restoreAlert}>{restoreError}</p>{/if}
	<div class="stack-6">
		{#if isOwner}
			<div class="card">
				<SettingRow label="Back up now" desc="Runs in the background; the history below follows it.">
					<button class="btn btn-primary" type="button" disabled={busy} onclick={start}>Back up now</button>
				</SettingRow>
			</div>
		{/if}
		{#if data.backups.length === 0}
			<div class="card empty" id="backups-empty">
				<h2>No backups yet</h2>
				<p>{isOwner ? 'Back up now, or wait for the scheduled run.' : 'None has been taken yet; the scheduled run will take the first.'}</p>
			</div>
		{:else}
			<div>
				<div class="card table-wrap" id="backup-history">
					<table class="table">
						<thead>
							<tr><th>Taken</th><th class="num">Size</th><th class="num">Took</th><th>Status</th><th>Contents</th><th><span class="sr-only">Actions</span></th></tr>
						</thead>
						<tbody>
							{#each data.backups as b (b.id)}
								<tr>
									<td>{taken(b.created_at)}</td>
									<td class="num">{b.size_bytes === null ? '—' : humanBytes(b.size_bytes)}</td>
									<td class="num">{b.took}</td>
									<td>
										<span class="badges">
											<StatusBadge status={b.status} />
											{#if b.status === 'ok'}
												{#if b.verified}
													<StatusBadge status="verified" title="Read back in full after it was written." />
												{:else}
													<StatusBadge
														status="unverified"
														title="This backup was written but never read back: either verification was off, or it predates the check."
													/>
												{/if}
											{/if}
										</span>
										{#if b.error}<div class="sub">{b.error}</div>{/if}
									</td>
									<td>
										{#if b.contents.state === 'unknown'}
											<StatusBadge status="unknown" title={b.contents.detail ?? undefined} />
										{:else if b.contents.state === 'needs_care'}
											<StatusBadge status="needs_care" title={b.contents.detail ?? undefined} />
										{:else}
											<StatusBadge status="recorded" />
										{/if}
									</td>
									<td class="act">
										<!-- Only a finished backup can be restored: a running row has
										     no complete blob, a failed one is kept as evidence. -->
										{#if isOwner && b.status === 'ok'}
											<button
												class="btn btn-quiet btn-sm"
												type="button"
												disabled={busy}
												aria-label={`Restore from the backup taken ${taken(b.created_at)}`}
												onclick={() => (restoring = b)}>Restore</button
											>
										{/if}
									</td>
								</tr>
								{#if b.log}
									<tr class="logrow">
										<td colspan="6">
											<details>
												<summary>Show log</summary>
												<pre class="log">{b.log}</pre>
											</details>
										</td>
									</tr>
								{/if}
							{/each}
						</tbody>
					</table>
				</div>
				<p class="table-note">
					Deleting this database hands its backups to an administrator: they are kept, but you will no
					longer see or restore them.
				</p>
			</div>
		{/if}
	</div>
{/if}

{#if restores.length > 0}
	<h2 class="section-title">Restores</h2>
	<p class="section-desc">
		Each restore replaced this database with the contents of a backup. A failed one changed nothing:
		the whole dump is applied in one transaction, so it either all arrives or none of it does.
	</p>
	<div class="card table-wrap" id="restore-history">
		<table class="table">
			<thead><tr><th>Started</th><th>By</th><th>Status</th><th><span class="sr-only">Actions</span></th></tr></thead>
			<tbody>
				{#each restores as r (r.id)}
					<tr>
						<td>{taken(r.created_at)}</td>
						<td><code>{r.requested_by}</code></td>
						<td>
							<StatusBadge status={r.status} />
							{#if r.status === 'running'}
								<span class="sub">{r.stage_title ?? 'working'}…</span>
							{/if}
						</td>
						<td class="act"><a class="btn btn-quiet btn-sm" href={jobHref(r.id)}>View job</a></td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}

{#if restoring}
	{@const b = restoring}
	<TypedConfirmDialog
		title={`Restore ${name} from ${taken(b.created_at)}?`}
		message="This replaces everything in the database with its contents at that moment. If it fails, nothing changes; if it succeeds, there is no undo."
		expected={name}
		action="Restore"
		onconfirm={(typed) => restore(b, typed)}
		oncancel={() => (restoring = null)}
	/>
{/if}
