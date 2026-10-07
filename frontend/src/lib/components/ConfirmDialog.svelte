<script lang="ts">
	// A centred modal for a destructive decision —
	// it interrupts where the eyes are. Focus starts on Cancel so Enter does
	// nothing destructive; Escape and the backdrop cancel; Tab stays inside;
	// focus goes back to whatever opened it.
	import { onMount } from 'svelte';

	let {
		title,
		message,
		action = 'Confirm',
		onconfirm,
		oncancel
	}: {
		/** The question, naming the action and its object ("Remove 10.0.0.0/8?"). */
		title?: string;
		/** What will happen. Without a title, it is the question too. */
		message: string;
		/** The confirm button's verb. */
		action?: string;
		onconfirm: () => void;
		oncancel: () => void;
	} = $props();
	const uid = $props.id();

	let cancelBtn: HTMLButtonElement;
	let confirmBtn: HTMLButtonElement;

	onMount(() => {
		const opener = document.activeElement as HTMLElement | null;
		cancelBtn.focus();
		return () => opener?.focus?.();
	});

	function onkeydown(ev: KeyboardEvent) {
		if (ev.key === 'Escape') {
			oncancel();
		} else if (ev.key === 'Tab') {
			ev.preventDefault();
			(document.activeElement === cancelBtn ? confirmBtn : cancelBtn).focus();
		}
	}
</script>

<svelte:document {onkeydown} />

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div class="scrim" onclick={(ev) => ev.target === ev.currentTarget && oncancel()}>
	<div class="dialog" role="alertdialog" aria-modal="true" aria-label={title ?? 'Confirm action'}
		aria-describedby={`${uid}-msg`}>
		{#if title}<h2>{title}</h2>{/if}
		<p id={`${uid}-msg`} class:consequence={!!title}>{message}</p>
		<div class="btn-row">
			<button bind:this={cancelBtn} type="button" class="btn btn-quiet" onclick={oncancel}>Cancel</button>
			<button bind:this={confirmBtn} type="button" class="btn btn-danger-solid" onclick={onconfirm}>{action}</button>
		</div>
	</div>
</div>
