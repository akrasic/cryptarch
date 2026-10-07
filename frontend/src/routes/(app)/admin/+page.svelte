<script lang="ts">
	// The admin overview: the portal at a glance, then what recovery needs.
	import { resolve } from '$app/paths';
	import PageHeader from '#lib/components/PageHeader.svelte';
	import SettingRow from '#lib/components/SettingRow.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const o = $derived(data.overview);
</script>

<svelte:head><title>Admin — Cryptarch</title></svelte:head>

<PageHeader title="Overview" desc="The portal at a glance: who can sign in, what they hold, and where it runs." />

<div class="stats">
	<a class="card stat" href={resolve('/(app)/admin/users')}><span class="stat-n">{o.users}</span><span class="stat-l">Users</span></a>
	<a class="card stat" href={resolve('/(app)/admin/databases')}><span class="stat-n">{o.databases}</span><span class="stat-l">Databases</span></a>
	<a class="card stat" href={resolve('/(app)/admin/servers')}><span class="stat-n">{o.servers}</span><span class="stat-l">Servers</span></a>
</div>
<!-- Shown while backups are on, permanently and to every admin: the moment
     this warning is true is long before the moment it matters. Nothing here
     reveals the key. -->
{#if o.backups_enabled}
	<h2 class="section-title">Backups and your encryption key</h2>
	<div class="card">
		<SettingRow
			label="Keep a copy of the key off this machine"
			desc="Every backup is sealed with the key file, and it also encrypts the stored server credentials. If this machine is lost and the key with it, nobody can open the backups, including you. Copy it into a password manager once; it never changes."
		>
			<code class="setting-value">CRYPTARCH_KEY_FILE</code>
		</SettingRow>
		<SettingRow
			label="What a full recovery needs"
			desc="The backup directory, a backup of Cryptarch's own metadata database (taken automatically alongside the rest), and that key. All three, or none of it works."
		>
			<code class="setting-value">cryptarch</code>
		</SettingRow>
	</div>
{/if}
