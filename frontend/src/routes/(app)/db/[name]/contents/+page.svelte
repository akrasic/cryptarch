<script lang="ts">
	import { api } from '#lib/api.js';
	import ContentsPanel, { type Contents } from '#lib/components/ContentsPanel.svelte';
	import PageHeader from '#lib/components/PageHeader.svelte';
	import { section } from '#lib/sections.js';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const db = $derived(data.db);
	const s = section('contents');

	// A round trip to the managed server, so asked only on this page
	// (CRYPTARCH-115/141).
	const contents = $derived(api<Contents>('GET', `/databases/${encodeURIComponent(db.name)}/contents`));
</script>

<svelte:head><title>{s.title} · {db.name} — Cryptarch</title></svelte:head>

<PageHeader title={s.title} desc={s.desc} />
{#await contents}
	<p class="loading">Asking the server…</p>
{:then c}
	<ContentsPanel contents={c} />
{:catch e}
	<p class="alert alert-danger" role="alert">{e.message}</p>
{/await}
