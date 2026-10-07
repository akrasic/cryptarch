<script lang="ts">
	import { resolve } from '$app/paths';
	import PageHeader from '#lib/components/PageHeader.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const here = resolve('/(app)/admin/audit');
</script>

<svelte:head><title>Audit · Admin — Cryptarch</title></svelte:head>

<PageHeader
	title="Audit log"
	desc={`Every change anyone made, newest first, 200 a page. Nothing here can be edited or removed.${data.paged ? ' Showing older entries.' : ''}`}
/>
{#if data.entries.length === 0}
	<div class="card empty" id="audit-start">
		<h2>The start of the log</h2>
		<p>Nothing is older than this point.</p>
	</div>
{:else}
	<div class="card table-wrap">
		<table class="table" id="audit">
			<thead><tr><th>When (UTC)</th><th>Who</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
			<tbody>
				{#each data.entries as a (a.id)}
					<tr>
						<td class="stamp">{a.created_at.slice(0, 19).replace('T', ' ')}</td>
						<td>{a.actor}</td>
						<td><code>{a.action}</code></td>
						<td>{a.target ?? ''}</td>
						<td class="sub">{a.detail ?? ''}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
{#if data.paged || data.older !== null}
	<nav class="btn-row pager" aria-label="Audit log pages">
		{#if data.paged}<a class="btn btn-quiet" href={here}>← Newest</a>{/if}
		{#if data.older !== null}<a class="btn btn-quiet" href={`${here}?before=${data.older}`}>Older →</a>{/if}
	</nav>
{/if}
