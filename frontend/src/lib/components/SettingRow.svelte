<script lang="ts">
	// One settings-card row (the design system's SettingsCard): the setting's
	// name and what changing it does on the left, its control on the right.
	import type { Snippet } from 'svelte';

	let { label, desc, children }: { label: string; desc: string; children: Snippet } = $props();
</script>

<div class="setting">
	<div>
		<p class="setting-label">{label}</p>
		<p class="setting-desc">{desc}</p>
	</div>
	<div class="setting-control">{@render children()}</div>
</div>
