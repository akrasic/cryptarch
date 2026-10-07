<script lang="ts">
	// Your databases: list → manage. The quota is said in the header, and
	// what to do at the cap is said where the button would be.
	import { resolve } from '$app/paths';
	import PageHeader from '#lib/components/PageHeader.svelte';
	import StatusBadge from '#lib/components/StatusBadge.svelte';
	import { takeNotice } from '#lib/notice.svelte.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const quota = $derived(data.list.quota);
	const dbs = $derived(data.list.databases);
	// Left by the page we came from (a delete); shown once.
	const notice = takeNotice();

	const desc = $derived(
		!quota.known
			? 'Your quota could not be read just now; provisioning still enforces it. Open a database to connect, back it up or manage it.'
			: quota.limit === null
				? `${quota.used} in use; your account has no limit. Open one to connect, back it up or manage it.`
				: `${quota.used} of ${quota.limit} in use. Open one to connect, back it up or manage it.`
	);
	// A quota of none is not "full": there is nothing to delete to make room.
	const noQuota = $derived(quota.at_cap && quota.limit === 0);
</script>

<svelte:head><title>Your databases — Cryptarch</title></svelte:head>

<PageHeader title="Your databases" {desc}>
	{#snippet actions()}
		{#if !quota.at_cap && dbs.length > 0}
			<a class="btn btn-primary" href={resolve('/(app)/provision')}>New database</a>
		{/if}
	{/snippet}
</PageHeader>

{#if notice?.warning}<p class="alert alert-warn" role="alert">{notice.warning}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status">{notice.message}</p>{/if}
{#if noQuota}
	<p class="alert alert-warn" id="at-cap">
		<strong>No quota yet.</strong> Your account may not hold any databases. Ask an administrator for a quota.
	</p>
{:else if quota.at_cap}
	<p class="alert alert-warn" id="at-cap">
		<strong>Quota reached.</strong> You hold {quota.used} of {quota.limit}. Delete one to provision another,
		or ask an administrator for a higher quota.
	</p>
{/if}

{#if !data.list.listed}
	<div class="card empty empty-blind" id="list-unavailable">
		<h2>Your databases could not be loaded</h2>
		<p>The list could not be read just now, so there may be databases here that it does not show. Refresh to try again.</p>
	</div>
{:else if dbs.length === 0}
	<div class="card empty" id="no-databases">
		<h2>No databases yet</h2>
		{#if quota.at_cap}
			<p>Your quota does not allow one yet.</p>
		{:else}
			<p>Provision one: you pick the server and the name, and get its password, shown once.</p>
			<div class="btn-row"><a class="btn btn-primary" href={resolve('/(app)/provision')}>New database</a></div>
		{/if}
	</div>
{:else}
	<div class="card table-wrap">
		<table class="table" id="databases">
			<thead><tr><th>Database</th><th>Server</th><th>Status</th><th aria-hidden="true"></th></tr></thead>
			<tbody>
				{#each dbs as d (d.name)}
					{@const href = resolve('/(app)/db/[name]/connect', { name: d.name })}
					<tr>
						<td><a class="row-link" {href}>{d.name}</a></td>
						<td class="sub">{d.server_name}</td>
						<td><StatusBadge status={d.status} /></td>
						<!-- The same place as the name's link: one stop for the keyboard and
						     one entry in a screen reader's link list, not two. -->
						<td class="act" aria-hidden="true"><a class="btn btn-quiet btn-sm" {href} tabindex="-1">Manage</a></td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
{/if}
