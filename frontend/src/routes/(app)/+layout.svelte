<script lang="ts">
	// The app shell (CRYPTARCH-151): one sidebar, which follows where you are,
	// and one content column. At phone width the sidebar becomes a drawer
	// behind the top bar's menu, and inside a database or server a switcher
	// names the section you are in. Links go through resolve(), which only
	// accepts routes that exist, so the type checker catches a dead one.
	import { afterNavigate, goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import { tick } from 'svelte';
	import { api, ApiError } from '#lib/api.js';
	import { navFor } from '#lib/nav.js';
	import { takeNotice } from '#lib/notice.svelte.js';
	import Sidebar from '#lib/components/Sidebar.svelte';
	import StatusBadge from '#lib/components/StatusBadge.svelte';
	import type { LayoutProps } from './$types';

	let { data, children }: LayoutProps = $props();

	// By route id rather than URL, so the rule does not depend on the base path.
	const nav = $derived(
		navFor({
			routeId: page.route.id ?? '',
			isAdmin: data.me.is_admin,
			db: page.data.db,
			server: page.data.server
		})
	);

	let signOutError = $state<string | null>(null);

	// Leaves only once the server has ended the session. Going to the login
	// page after a failed DELETE would look like a sign-out while the session
	// is still live — on a shared machine, the opposite of what was asked.
	async function signOut() {
		signOutError = null;
		try {
			await api('DELETE', '/session');
		} catch (e) {
			// Already signed out server-side is a sign-out all the same.
			if (!(e instanceof ApiError && e.status === 401)) {
				signOutError = e instanceof ApiError ? e.message : 'Sign-out failed — try again.';
				return;
			}
		}
		// A notice left for the next page is this user's; the next one to sign
		// in on this tab must not see it.
		takeNotice();
		await goto(resolve('/login'));
	}

	// The phone drawer. Focus goes in when it opens and back to whatever
	// opened it when it closes; Escape and the backdrop close it, and so does
	// following any link in it. While it is open the page behind it is inert,
	// so Tab cannot walk out of the dialog onto controls under the scrim.
	let drawerOpen = $state(false);
	let drawer = $state<HTMLDivElement>();
	let opener: HTMLElement | null = null;

	async function openDrawer(ev: MouseEvent) {
		opener = ev.currentTarget as HTMLElement;
		drawerOpen = true;
		await tick();
		// The section you are on, else the first link: a selector list would
		// take whichever comes first in the document, which is the logo.
		(drawer?.querySelector<HTMLElement>('a.side-item[aria-current]') ?? drawer?.querySelector<HTMLElement>('a'))?.focus();
	}
	function closeDrawer() {
		if (!drawerOpen) return;
		drawerOpen = false;
		opener?.focus();
	}
	afterNavigate(() => {
		drawerOpen = false;
	});
</script>

<svelte:window onkeydown={(ev) => ev.key === 'Escape' && closeDrawer()} />

<div class="shell" inert={drawerOpen}>
	<aside class="shell-side">
		<Sidebar {nav} me={data.me} {signOutError} onsignout={signOut} />
	</aside>
	<div class="shell-body">
		<header class="phonebar">
			<button class="menu-btn" type="button" aria-label="Open navigation" aria-expanded={drawerOpen} onclick={openDrawer}
				><span></span></button
			>
			<a class="brand" href={resolve('/(app)/dashboard')}><span class="mark" aria-hidden="true"></span>Cryptarch</a>
			<span class="who">{data.me.username}</span>
		</header>
		<main class="shell-main">
			<div class="inner">
				{#if nav.scope}
					<!-- The scope card lives in the drawer on a phone, so the status rides
					     here: a database being deleted must not look normal until the
					     menu is opened. -->
					<button
						class="switcher"
						type="button"
						aria-haspopup="dialog"
						aria-expanded={drawerOpen}
						aria-label={`${nav.scope.name}, ${nav.scope.status}, ${nav.here ?? ''}. Open sections`}
						onclick={openDrawer}
						><span class="sw-name">{nav.scope.name} <StatusBadge status={nav.scope.status} /></span><b>{nav.here}</b></button
					>
				{/if}
				{@render children()}
			</div>
		</main>
	</div>
</div>

{#if drawerOpen}
	<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
	<div class="drawer-scrim" onclick={closeDrawer}></div>
	<div class="drawer" role="dialog" aria-modal="true" aria-label="Navigation" bind:this={drawer}>
		<Sidebar {nav} me={data.me} {signOutError} onsignout={signOut} />
	</div>
{/if}
