<script lang="ts" module>
	export interface Job {
		id: string;
		db_name: string;
		/** Cryptarch's own metadata database: there is no page to link to. */
		metadata: boolean;
		created_at: string;
		size_bytes: number | null;
		took: string;
		status: string;
		error: string | null;
		log: string;
		verified: boolean;
		contents: { state: 'unknown' | 'needs_care' | 'recorded'; detail: string | null };
	}
	export interface Jobs {
		configured: boolean;
		running: boolean;
		jobs: Job[];
	}
	export interface LeftBehind {
		configured: boolean;
		backups: {
			id: string;
			db_name: string;
			created_at: string;
			status: string;
			size_bytes: number | null;
			/** null: it could not be looked for — neither present nor missing. */
			file_present: boolean | null;
		}[];
		recorded_bytes: number;
		missing: number;
		unchecked: number;
	}
	export interface Unreferenced {
		configured: boolean;
		files: { rel: string; size_bytes: number; recognised: boolean }[];
		total_bytes: number;
	}
</script>

<script lang="ts">
	// The admin Backups page. Three reads: the jobs list, which this follows while a
	// job runs (CRYPTARCH-144's lib/poll), and the two lists that walk the
	// backup disk, which it never re-reads on that schedule (CRYPTARCH-124) —
	// only after a purge, through `onchanged`.
	import { onMount, tick } from 'svelte';
	import { api, ApiError } from '#lib/api.js';
	import { humanBytes } from '#lib/format.js';
	import { poll, type Poller } from '#lib/poll.js';
	import ConfirmDialog from './ConfirmDialog.svelte';
	import PageHeader from './PageHeader.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let {
		leftBehind,
		unreferenced,
		scanError,
		onchanged,
		dbHref
	}: {
		leftBehind: LeftBehind;
		/** null when the scan failed; `scanError` says why. */
		unreferenced: Unreferenced | null;
		scanError: string | null;
		onchanged: () => Promise<void>;
		dbHref: (name: string) => string;
	} = $props();

	let data = $state<Jobs | null>(null);
	let loadError = $state<string | null>(null);
	let poller: Poller | null = null;

	type Pending = { kind: 'backup'; id: string; dbName: string } | { kind: 'file'; rel: string };
	let pending = $state<Pending | null>(null);
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	let alertEl = $state<HTMLElement>();
	let noticeEl = $state<HTMLElement>();

	onMount(() => {
		poller = poll<Jobs>({
			fetch: () => api<Jobs>('GET', '/admin/backups'),
			running: (j) => j.running,
			onValue: (j) => ([data, loadError] = [j, null]),
			onError: (e) => {
				loadError = (e as Error).message;
				if (e instanceof ApiError && [401, 403].includes(e.status)) poller?.stop();
			}
		});
		return () => poller?.stop();
	});

	const failed = $derived(data?.jobs.filter((j) => j.status === 'failed').length ?? 0);
	const unverified = $derived(data?.jobs.filter((j) => j.status === 'ok' && !j.verified).length ?? 0);

	async function confirm(p: Pending) {
		pending = null;
		if (busy) return;
		busy = true;
		error = notice = null;
		try {
			if (p.kind === 'backup') {
				const r = await api<{ outcome: string }>('POST', `/admin/backups/${encodeURIComponent(p.id)}/purge`);
				notice =
					r.outcome === 'with_file'
						? `Purged the backup of ${p.dbName}, and its file.`
						: `Purged the backup of ${p.dbName}. Its file was already missing, so no space was reclaimed.`;
			} else {
				const r = await api<{ size_bytes: number }>('POST', '/admin/backups/purge-file', { rel: p.rel });
				notice = `Deleted ${p.rel} (${humanBytes(r.size_bytes)}).`;
			}
			await onchanged();
			// The jobs list is this component's own, not the page load's.
			poller?.kick();
			// The row and its button are gone: focus goes to what happened.
			tick().then(() => noticeEl?.focus());
		} catch (e) {
			error = (e as Error).message;
			// The dialog has closed and its row's button is disabled meanwhile:
			// the refusal takes focus, not the page.
			tick().then(() => alertEl?.focus());
			// Already gone, or now someone's: the list on screen is stale.
			if (e instanceof ApiError && ['no_such_backup', 'no_such_file', 'now_referenced'].includes(e.code))
				await onchanged();
		} finally {
			busy = false;
		}
	}

	// "%Y-%m-%d %H:%M UTC", as the server words times.
	const taken = (iso: string) => iso.slice(0, 16).replace('T', ' ') + ' UTC';
	const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);
</script>

<PageHeader
	title="Backups"
	desc="Every backup job, newest first, including Cryptarch's own metadata database (_cryptarch_meta): the one that holds who owns what, and the one you rebuild from."
/>
{#if !leftBehind.configured}
	<p class="alert alert-warn" id="backups-off">
		<strong>Backups are off.</strong> Set CRYPTARCH_BACKUP_DIR to turn them on.
	</p>
{/if}
{#if failed > 0 || unverified > 0}
	<p class="alert alert-warn" id="backup-counts">
		{#if failed > 0}<strong>{failed} failed.</strong>{/if}
		{#if unverified > 0}<strong>{unverified}</strong> succeeded but were never read back: see the Status column.{/if}
	</p>
{/if}
{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status" tabindex="-1" bind:this={noticeEl}>{notice}</p>{/if}

<!-- Nothing else can see or remove these: the owner lost sight of them when
     the database was deleted, and retention leaves them alone on purpose. -->
<h2 class="section-title first">Left behind by deleted databases</h2>
{#if leftBehind.backups.length === 0}
	<div class="card empty" id="left-behind-empty">
		<h3>Nothing left behind</h3>
		<p>Every backup belongs to a database that still exists.</p>
	</div>
{:else}
	<p class="section-desc">
		When a database is deleted its backups stop being the owner's and become yours. Retention never touches
		them, so they stay until you purge them here.
	</p>
	<div class="card table-wrap">
		<table class="table" id="left-behind">
			<thead><tr><th>Taken</th><th>Was</th><th class="num">Size</th><th>File</th><th><span class="sr-only">Actions</span></th></tr></thead>
			<tbody>
				{#each leftBehind.backups as b (b.id)}
					<tr>
						<td class="stamp">{taken(b.created_at)}</td>
						<td><code>{b.db_name}</code></td>
						<td class="num">{b.size_bytes === null ? '—' : humanBytes(b.size_bytes)}</td>
						<td>
							{#if b.file_present === true}
								<StatusBadge status={b.status} />
							{:else if b.file_present === null}
								<span class="badge badge-unknown" title="Whether this backup's file is on the backup disk could not be checked.">Not checked</span>
							{:else}
								<span class="badge badge-warn" title="The row says this backup exists, but its file is not on the backup disk. Purging it will reclaim no space.">File missing</span>
							{/if}
						</td>
						<td class="act">
							<button
								class="btn btn-quiet btn-sm"
								type="button"
								disabled={busy}
								aria-label={`Purge the backup of ${b.db_name} taken ${taken(b.created_at)}`}
								onclick={() => (pending = { kind: 'backup', id: b.id, dbName: b.db_name })}>Purge</button
							>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<p class="table-note" id="left-behind-totals">
		<strong>{leftBehind.backups.length}</strong>
		{plural(leftBehind.backups.length, 'backup', 'backups')}, <strong>{humanBytes(leftBehind.recorded_bytes)}</strong>
		recorded{#if leftBehind.missing > 0}
			— but <strong>{leftBehind.missing}</strong>
			{plural(leftBehind.missing, 'has', 'have')} no file on disk, so that total is larger than what you would reclaim.{/if}{#if leftBehind.unchecked > 0}
			— <strong>{leftBehind.unchecked}</strong> could not be checked for a file on disk.{/if}
	</p>
{/if}

<!-- A record and no owner, above; no record at all, here. -->
<h2 class="section-title">Files with no record</h2>
{#if !unreferenced}
	<div class="card empty empty-blind" id="scan-failed">
		<h3>The backup disk could not be read</h3>
		<p>{scanError} There may be files here; Cryptarch cannot see them.</p>
	</div>
{:else if unreferenced.files.length === 0}
	<div class="card empty" id="unreferenced-empty">
		<h3>Nothing unaccounted for</h3>
		<p>Every file on the backup disk belongs to a backup this panel knows about.</p>
	</div>
{:else}
	<p class="section-desc">
		These files are on the backup disk, but nothing in the database points at them, so nothing else can find
		them and retention will never reclaim them. A crash between deleting a file and deleting its row leaves
		one, and so does restoring an older copy of the metadata database.
	</p>
	<div class="card table-wrap">
		<table class="table" id="unreferenced">
			<thead><tr><th>File</th><th class="num">Size</th><th><span class="sr-only">Actions</span></th></tr></thead>
			<tbody>
				{#each unreferenced.files as f (f.rel)}
					<tr>
						<td><code>{f.rel}</code></td>
						<td class="num">{humanBytes(f.size_bytes)}</td>
						<td class="act">
							<!-- Only a name Cryptarch writes can be matched to a backup.
							     Anything else is shown so a human can look at it. -->
							{#if f.recognised}
								<button
									class="btn btn-quiet btn-sm"
									type="button"
									disabled={busy}
									aria-label={`Delete ${f.rel}`}
									onclick={() => (pending = { kind: 'file', rel: f.rel })}>Delete</button
								>
							{:else}
								<span
									class="badge"
									title="This file's name is not one Cryptarch writes, so it cannot be matched to a backup. Listed so you can look at it; remove it by hand if it is yours."
									>Unrecognised</span
								>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<p class="table-note">
		<strong>{unreferenced.files.length}</strong>
		{plural(unreferenced.files.length, 'file', 'files')}, <strong>{humanBytes(unreferenced.total_bytes)}</strong> you
		would reclaim.
	</p>
{/if}

<h2 class="section-title">Recent jobs</h2>
{#if loadError}<p class="alert alert-danger" role="alert">{loadError}</p>{/if}
{#if !data}
	{#if !loadError}<p class="loading">Loading…</p>{/if}
{:else if data.jobs.length === 0}
	<div class="card empty" id="no-jobs">
		<h3>No backups have run yet</h3>
		<p>The first scheduled run will appear here, with every one after it.</p>
	</div>
{:else}
	<div class="card table-wrap" id="backup-fleet">
		<table class="table">
			<thead>
				<tr><th>Taken</th><th>Database</th><th class="num">Size</th><th class="num">Took</th><th>Status</th><th>Contents</th></tr>
			</thead>
			<tbody>
				{#each data.jobs as b (b.id)}
					<tr>
						<td class="stamp">{taken(b.created_at)}</td>
						<td>
							{#if b.metadata}
								<code>{b.db_name}</code> <span class="sub">Cryptarch's own</span>
							{:else}
								<a class="row-link" href={dbHref(b.db_name)}>{b.db_name}</a>
							{/if}
						</td>
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
											title="Written but never read back: either verification was off, or this predates the check."
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
{/if}

{#if pending}
	{@const p = pending}
	<ConfirmDialog
		title={p.kind === 'backup' ? `Purge this backup of ${p.dbName}?` : `Delete ${p.rel}?`}
		message={p.kind === 'backup'
			? 'It is the only remaining copy, and this cannot be undone.'
			: 'Nothing points at this file, but if you put it there during a recovery it will be gone.'}
		action={p.kind === 'backup' ? 'Purge' : 'Delete'}
		onconfirm={() => confirm(p)}
		oncancel={() => (pending = null)}
	/>
{/if}
