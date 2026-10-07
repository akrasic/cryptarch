<script lang="ts">
	// The top of every page (the design system's PageHeader): the section's
	// name as the page's one h1, one line on what the page is for, and its
	// actions. No breadcrumb: the sidebar says where you are.
	import type { Snippet } from 'svelte';

	let { title, desc, actions }: { title: string; desc?: string; actions?: Snippet } = $props();
</script>

<div class="page-head">
	<h1>{title}</h1>
	{#if desc}<p>{desc}</p>{/if}
	{#if actions}<div class="actions">{@render actions()}</div>{/if}
</div>
