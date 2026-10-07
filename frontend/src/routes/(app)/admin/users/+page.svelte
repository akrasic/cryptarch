<script lang="ts">
	// The users list: list → manage.
	import { resolve } from '$app/paths';
	import PageHeader from '#lib/components/PageHeader.svelte';
	import StatusBadge from '#lib/components/StatusBadge.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
</script>

<svelte:head><title>Users · Admin — Cryptarch</title></svelte:head>

<PageHeader title="Users" desc="Everyone who can sign in: their role, how much of their quota they use, and whether they can sign in now.">
	{#snippet actions()}<a class="btn btn-primary" href={resolve('/(app)/admin/users/new')}>Add user</a>{/snippet}
</PageHeader>

<div class="card table-wrap">
	<table class="table" id="users">
		<thead><tr><th>User</th><th>Role</th><th class="num">Databases</th><th>Status</th><th aria-hidden="true"></th></tr></thead>
		<tbody>
			{#each data.users as u (u.id)}
				{@const href = resolve('/(app)/admin/users/[id]', { id: u.id })}
				<tr>
					<td>
						<a class="row-link" {href}>{u.username}</a>
						{#if u.username === data.me.username}<span class="sub">you</span>{/if}
					</td>
					<td class="sub">{u.is_admin ? 'Administrator' : 'User'}</td>
					<td class="num">{u.used} of {u.quota ?? 'unlimited'}</td>
					<td><StatusBadge status={u.is_active ? 'active' : 'suspended'} /></td>
					<td class="act" aria-hidden="true"><a class="btn btn-quiet btn-sm" {href} tabindex="-1">Manage</a></td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>
