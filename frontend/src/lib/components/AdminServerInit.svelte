<script lang="ts" module>
	export interface InitReport {
		status: string;
		steps: { step: string; ok: boolean; detail: string }[];
		bootstrap_sql: string | null;
		/** The bouncer auth role's userlist.txt line: a password in the clear. */
		userlist_line: string | null;
	}
</script>

<script lang="ts">
	// Server init's report. The userlist line carries the auth role's
	// password: held in this component only, gone on pagehide, on Done, and
	// when the page is left (dec D8).
	import { onMount } from 'svelte';
	import CopyButton from './CopyButton.svelte';

	let { report, ondone }: { report: InitReport; ondone: () => void } = $props();

	onMount(() => {
		window.addEventListener('pagehide', ondone);
		return () => window.removeEventListener('pagehide', ondone);
	});
</script>

<section class="card" aria-labelledby="init-h">
	<div class="card-head"><h2 id="init-h">Server init</h2></div>
	<div class="table-wrap">
		<table class="table" id="init-steps">
			<tbody>
				{#each report.steps as s, i (i)}
					<tr>
						<td>{s.step}</td>
						<td><span class={s.ok ? 'badge badge-ok badge-wrap' : 'badge badge-danger badge-wrap'}>{s.detail}</span></td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	{#if report.bootstrap_sql || report.userlist_line}
		<div class="card-body">
			{#if report.bootstrap_sql}
				<p class="lead">Run this once as a superuser on the managed server, then run init again:</p>
				<pre class="block" id="bootstrap-sql">{report.bootstrap_sql}</pre>
				<div class="btn-row"><CopyButton text={report.bootstrap_sql} label="Copy bootstrap SQL" /></div>
			{/if}
			{#if report.userlist_line}
				<p class="lead">
					<strong>Save this now:</strong> add this line to the bouncer's <code>userlist.txt</code>. No conf dir is
					configured, so Cryptarch cannot write it. It holds the bouncer auth role's password, and is shown only here.
				</p>
				<pre class="block" id="userlist-line">{report.userlist_line}</pre>
				<div class="btn-row"><CopyButton text={report.userlist_line} label="Copy userlist line" /></div>
			{/if}
		</div>
	{/if}
	<div class="card-foot"><button class="btn" type="button" onclick={ondone}>Done</button></div>
</section>
