<script lang="ts" module>
	export interface ServerLogins {
		server_name: string;
		verdict: 'not_checked' | 'partial' | 'not_surveyed' | 'inconclusive' | 'sources_disagree' | 'clean' | 'findings';
		detail: string | null;
		roles_checked: number | null;
		roles_failed: number | null;
		known_databases: number | null;
		disabled: { role_name: string; db_name: string | null; cause: string }[];
		unknown_to_metadata: string[];
	}
	export interface Logins {
		summary: { findings: number; checked: number; unchecked: number };
		servers: ServerLogins[];
		/** null: the server could not be asked. */
		stranded: { name: string; can_log_in: boolean | null; db_exists: boolean | null; retryable: boolean }[];
		unreachable_at_upgrade: { server_name: string; detail: string }[];
	}
</script>

<script lang="ts">
	// The login report. Every verdict is the server's
	// (ServerReport::verdict); this only words it. Each
	// coverage state reads differently — "could not look" is never "clean".
	import { tick } from 'svelte';
	import { api } from '#lib/api.js';
	import PageHeader from './PageHeader.svelte';
	import TypedConfirmDialog from './TypedConfirmDialog.svelte';

	let { report, onchanged }: { report: Logins; onchanged: () => Promise<void> } = $props();

	const s = $derived(report.summary);
	let finishing = $state<Logins['stranded'][number] | null>(null);
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	let alertEl = $state<HTMLElement>();
	let noticeEl = $state<HTMLElement>();

	const cause = (c: string) =>
		c === 'failed_delete'
			? 'A delete began and did not finish.'
			: c === 'disabled_outside_cryptarch'
				? 'Disabled outside Cryptarch, likely by hand.'
				: 'Cause unknown. Not attributed, and never repaired automatically.';

	async function finish(name: string, typed: string) {
		finishing = null;
		if (busy) return;
		busy = true;
		error = notice = null;
		try {
			await api('POST', `/admin/logins/${encodeURIComponent(name)}/retry-delete`, { confirm: typed });
			notice = 'Delete completed.';
			await onchanged();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
		// The dialog has closed and the row's button was disabled meanwhile, or
		// the row is gone: focus goes to what happened, not to the page.
		await tick();
		(error ? alertEl : noticeEl)?.focus();
	}
</script>

<PageHeader
	title="Login report"
	desc="Roles Cryptarch administers whose login is disabled. Cryptarch no longer disables logins, so these were disabled outside it, or by a delete that did not finish."
/>
{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status" tabindex="-1" bind:this={noticeEl}>{notice}</p>{/if}
<!-- Always two numbers: a summary that can only say "clean" lies whenever
     anything was inconclusive. -->
<p class={s.unchecked === 0 ? 'summary alert' : 'summary alert alert-warn'}>
	{#if s.findings === 0}No findings on {s.checked} server(s).{:else}{s.findings} finding(s) across {s.checked} server(s).{/if}
	{#if s.unchecked === 0}
		0 servers could not be checked.
	{:else}
		<strong>{s.unchecked} server(s) could not be checked - this report is incomplete.</strong>
	{/if}
</p>

<div class="stack-6">
	{#each report.servers as r, i (i)}
		<section class="card server-report">
			<div class="card-head">
				<h2>{r.server_name}</h2>
				{#if r.verdict === 'not_checked'}
					<span class="badge badge-unknown">Not checked</span>
				{:else if r.verdict === 'partial'}
					<span class="badge badge-warn">Partially checked</span>
				{:else if r.verdict === 'not_surveyed'}
					<span class="badge badge-unknown">Not surveyed</span>
				{:else if r.verdict === 'inconclusive'}
					<span class="badge badge-unknown">Inconclusive</span>
				{:else if r.verdict === 'sources_disagree'}
					<span class="badge badge-danger">Sources disagree</span>
				{:else if r.verdict === 'clean'}
					<span class="badge badge-ok">Checked</span>
				{:else if r.verdict === 'findings'}
					<!-- Fully checked, and something was found: not a green state. -->
					<span class="badge badge-warn">Findings</span>
				{:else}
					<!-- A verdict this page does not know is never a green "checked". -->
					<span class="badge badge-danger">Unknown</span>
				{/if}
			</div>
			<div class="card-body">
				{#if r.verdict === 'not_checked'}
					<p>The server could not be surveyed: {r.detail}</p>
					<p>This is not a clean result. Nothing here was ruled out.</p>
				{:else if r.verdict === 'partial'}
					<p>
						{r.roles_checked} role(s) checked, {r.roles_failed} could not be. Findings below are real, but absence
						proves nothing.
					</p>
				{:else if r.verdict === 'not_surveyed'}
					<p>{r.detail}</p>
					<p>Its databases and roles still exist. Nothing here was ruled out.</p>
				{:else if r.verdict === 'inconclusive'}
					<p>
						Cryptarch administers no roles on this server, and the number of databases it should have could not be
						determined. This is not a clean result.
					</p>
				{:else if r.verdict === 'sources_disagree'}
					<p>
						Cryptarch administers no roles on this server, but metadata lists {r.known_databases} database(s) here.
						Either those databases predate the panel owning their roles, or this metadata is ahead of the server.
					</p>
				{:else if r.verdict === 'clean'}
					<p>Checked {r.roles_checked} role(s). No findings.</p>
				{:else if r.verdict === 'findings'}
					<p>Checked {r.roles_checked} role(s).</p>
				{:else}
					<p>This report says something this page does not understand. Not a clean result.</p>
				{/if}
				{#if (r.verdict === 'partial' || r.verdict === 'findings') && r.unknown_to_metadata.length > 0}
					<p>
						Roles Cryptarch administers that metadata does not name:
						{#each r.unknown_to_metadata as n, j (j)}{#if j > 0},&nbsp;{/if}<code>{n}</code>{/each}
					</p>
				{/if}
			</div>
			{#if (r.verdict === 'partial' || r.verdict === 'findings') && r.disabled.length > 0}
				<div class="table-wrap">
					<table class="table">
						<thead><tr><th>Role</th><th>Database</th><th>Cause</th></tr></thead>
						<tbody>
							{#each r.disabled as d, j (j)}
								<tr>
									<td><code>{d.role_name}</code></td>
									<td>{#if d.db_name}<code>{d.db_name}</code>{:else}<span class="sub">not in metadata</span>{/if}</td>
									<td>{cause(d.cause)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>
	{/each}
</div>

{#if report.stranded.length > 0}
	<h2 class="section-title">Unfinished deletes</h2>
	<p class="section-desc">
		A delete began on these and did not finish. They are shown here because nothing retries a delete
		automatically: completing one destroys data, and that decision is yours.
	</p>
	<div class="card" id="stranded">
		{#each report.stranded as st (st.name)}
			<div class="setting">
				<div>
					<p class="setting-label"><code>{st.name}</code></p>
					{#if st.can_log_in === null || st.db_exists === null}
						<p class="setting-desc">
							The server could not be asked, so whether finishing this is safe is unknown. Not offered until it can
							be checked.
						</p>
					{:else if st.can_log_in && !st.db_exists}
						<p class="setting-desc">
							Its login is enabled but the database is not on the server. A delete turns the login off first, so
							this is not a half-finished delete; something else may be provisioning this name. Not offered.
						</p>
					{:else if !st.retryable}
						<p class="setting-desc">
							This delete failed before it changed anything: the database is intact and still serving. A
							maintenance pass will return it to service shortly; no action is needed. To delete it, use its own
							page once it is back.
						</p>
					{:else}
						<p class="setting-desc">
							{st.db_exists
								? 'Part of this delete completed and the database is no longer usable. Finishing the job will permanently destroy it and everything in it. This cannot be undone.'
								: 'The database itself is already gone. Finishing the job only removes the leftover login role: there is no data left to lose.'}
						</p>
					{/if}
				</div>
				<div class="setting-control">
					{#if st.can_log_in === null || st.db_exists === null}
						<span class="badge badge-unknown">Not checked</span>
					{:else if st.can_log_in && !st.db_exists}
						<span class="badge badge-warn">Not ours to finish</span>
					{:else if !st.retryable}
						<span class="badge badge-ok">Intact</span>
					{:else}
						<button
							type="button"
							class="btn btn-danger"
							disabled={busy}
							aria-label={`Finish deleting ${st.name}`}
							onclick={() => (finishing = st)}
							>Finish delete</button
						>
					{/if}
				</div>
			</div>
		{/each}
	</div>
{/if}

{#if report.unreachable_at_upgrade.length > 0}
	<h2 class="section-title">Outstanding from the upgrade</h2>
	<p class="section-desc">
		These servers could not be reached when the one-time login repair ran. It will not be retried. Any login
		disabled by the old suspend feature is still disabled on them, and must be re-enabled by hand.
	</p>
	<div class="card">
		{#each report.unreachable_at_upgrade as u, i (i)}
			<div class="setting">
				<div><p class="setting-label">{u.server_name}</p><p class="setting-desc">{u.detail}</p></div>
				<div class="setting-control"><span class="badge badge-warn">Re-enable by hand</span></div>
			</div>
		{/each}
	</div>
{/if}

{#if finishing}
	{@const st = finishing}
	<TypedConfirmDialog
		title={`Finish deleting ${st.name}?`}
		message={st.db_exists
			? 'This permanently destroys it and everything in it.'
			: 'Only its leftover login role remains to remove.'}
		expected={st.name}
		action="Finish delete"
		onconfirm={(typed) => finish(st.name, typed)}
		oncancel={() => (finishing = null)}
	/>
{/if}
