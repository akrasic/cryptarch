<script lang="ts">
	// The show-once credentials panel. The credential lives in
	// this component's props only: never a store, never storage, never the URL
	// (dec D8). It is gone the moment the page is left.
	import { onMount } from 'svelte';
	import CopyButton from './CopyButton.svelte';

	export interface Shown {
		name: string;
		username: string;
		password: string;
		conn: string;
		via: { label: string; conn: string }[];
		/** Set only by a password reset whose new hash could not be recorded. */
		unrecorded?: boolean;
	}

	let {
		heading,
		shown,
		level = 'h1',
		takeFocus = false
	}: {
		heading: string;
		shown: Shown;
		/** h2 where it renders inside a page that already has its h1. */
		level?: 'h1' | 'h2';
		/** Shown in place of the control that asked for it, which is gone:
		 *  focus comes here instead of falling to the page. */
		takeFocus?: boolean;
	} = $props();
	const uid = $props.id();
	let section: HTMLElement;
	onMount(() => {
		if (takeFocus) section.focus();
	});
</script>

<section class="once" aria-labelledby={`${uid}-h`} tabindex="-1" bind:this={section}>
	<div class="once-head">
		<svelte:element this={level} id={`${uid}-h`}>{heading}</svelte:element>
		<p>
			Database <code>{shown.name}</code> is live. <strong>Save these now</strong>: the password is shown
			once and is not stored anywhere.
		</p>
	</div>
	{#if shown.unrecorded}
		<p class="alert alert-danger" role="alert">
			<strong>Saved on the server, not in Cryptarch.</strong> The password below is live and the old one
			has already stopped working, but Cryptarch could not record the change. Save it now, then tell an
			admin: this database's stored record is out of date until someone resets it again.
		</p>
	{/if}
	<dl>
		<dt>Username</dt>
		<dd><code class="well">{shown.username}</code><CopyButton text={shown.username} label="Copy username" /></dd>
		<dt>Password</dt>
		<dd><code class="well">{shown.password}</code><CopyButton text={shown.password} label="Copy password" /></dd>
		<dt>Connection string</dt>
		<dd><code class="well">{shown.conn}</code><CopyButton text={shown.conn} label="Copy connection string" /></dd>
		<!-- Not keyed by label: labels are not unique per server (two "lan" addresses
		     is a normal setup), and a duplicate each-key throws — which, on this
		     screen, destroyed the only copy of a show-once password (CRYPTARCH-139). -->
		{#each shown.via as v, i (i)}
			<dt>Via {v.label}</dt>
			<dd>
				<code class="well">{v.conn}</code><CopyButton text={v.conn} label={'Copy connection string via ' + v.label} />
			</dd>
		{/each}
	</dl>
	{#if shown.via.length > 0}
		<p class="note">Same credentials on every address: use whichever network the consumer lives on.</p>
	{/if}
	<p class="note">
		Lost it later? Use <strong>Reset password</strong> under the database's Manage page to get a new one;
		the old one stops working.
	</p>
</section>
