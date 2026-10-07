<script lang="ts">
	// The copy button, with its copied/failed flash.
	import { copyText } from '#lib/clipboard.js';

	let { text, label }: { text: string; label: string } = $props();

	let state = $state<'rest' | 'copied' | 'failed'>('rest');
	let timer: ReturnType<typeof setTimeout> | undefined;

	async function copy() {
		clearTimeout(timer);
		try {
			await copyText(text);
			state = 'copied';
		} catch {
			state = 'failed';
		}
		timer = setTimeout(() => (state = 'rest'), 1600);
	}
</script>

<button
	class="btn btn-sm"
	class:is-copied={state === 'copied'}
	class:is-failed={state === 'failed'}
	type="button"
	aria-label={label}
	onclick={copy}
>
	{state === 'copied' ? 'Copied' : state === 'failed' ? 'Select it to copy' : 'Copy'}
</button>
