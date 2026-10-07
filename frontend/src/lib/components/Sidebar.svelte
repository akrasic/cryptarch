<script lang="ts">
	// The app's only navigation (CRYPTARCH-151). What it lists comes from
	// navFor(); this only draws it. The same component is the desktop rail and
	// the phone drawer.
	import { resolve } from '$app/paths';
	import type { Me } from '#lib/api.js';
	import type { Nav } from '#lib/nav.js';
	import StatusBadge from './StatusBadge.svelte';

	let {
		nav,
		me,
		signOutError,
		onsignout
	}: { nav: Nav; me: Me; signOutError: string | null; onsignout: () => void } = $props();

	const label = $derived(
		nav.scope ? `${nav.scope.kind === 'database' ? 'Database' : 'Server'} ${nav.scope.name}` : 'Cryptarch'
	);
</script>

<nav class="sidebar" aria-label={label}>
	<a class="brand" href={resolve('/(app)/dashboard')}><span class="mark" aria-hidden="true"></span>Cryptarch</a>

	{#if nav.scope}
		<a class="side-back" href={nav.scope.back.href}>← {nav.scope.back.label}</a>
		<div class="side-scope">
			<span class="side-scope-name">{nav.scope.name} <StatusBadge status={nav.scope.status} /></span>
			<span class="side-scope-meta">{nav.scope.meta}</span>
		</div>
	{/if}

	{#each nav.groups as group, g (g)}
		<div class="side-group">
			{#if group.label}<span class="side-label">{group.label}</span>{/if}
			{#each group.items as item (item.href)}
				<a class="side-item" href={item.href} aria-current={item.current || undefined}>{item.label}</a>
			{/each}
		</div>
	{/each}

	<div class="side-foot">
		<a
			class="side-account"
			href={resolve('/(app)/profile')}
			aria-current={nav.profileCurrent ? 'page' : undefined}
			aria-label={`Your profile — signed in as ${me.username}`}
			><span class="side-user">{me.username}</span>{#if me.is_admin}<span class="side-role">Administrator</span>{/if}</a
		>
		<button class="side-signout" type="button" onclick={onsignout}>Sign out</button>
	</div>
	{#if signOutError}<p class="side-error" role="alert">{signOutError}</p>{/if}
</nav>
