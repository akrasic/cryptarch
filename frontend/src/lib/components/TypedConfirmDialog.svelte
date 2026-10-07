<script lang="ts">
	// ConfirmDialog for the irreversible kind: Confirm arms only once the name
	// is typed exactly (the server checks it again). Focus starts in the field;
	// Escape and the backdrop cancel; Tab stays inside; focus goes back to
	// whatever opened it.
	import { onMount } from 'svelte';

	let {
		title,
		message,
		expected,
		action = 'Confirm',
		onconfirm,
		oncancel
	}: {
		/** The question, naming the action and its object ("Delete eddy?"). */
		title?: string;
		/** What will happen, and what is kept. */
		message: string;
		expected: string;
		action?: string;
		onconfirm: (typed: string) => void;
		oncancel: () => void;
	} = $props();
	const uid = $props.id();

	let typed = $state('');
	const armed = $derived(typed.trim() === expected);
	let field: HTMLInputElement;
	let dialog: HTMLDivElement;

	onMount(() => {
		const opener = document.activeElement as HTMLElement | null;
		field.focus();
		return () => opener?.focus?.();
	});

	function onkeydown(ev: KeyboardEvent) {
		if (ev.key === 'Escape') {
			oncancel();
		} else if (ev.key === 'Tab') {
			const stops = [...dialog.querySelectorAll<HTMLElement>('input, button:not([disabled])')];
			const at = stops.indexOf(document.activeElement as HTMLElement);
			ev.preventDefault();
			stops[(at + (ev.shiftKey ? stops.length - 1 : 1)) % stops.length]?.focus();
		}
	}

	function submit(ev: SubmitEvent) {
		ev.preventDefault();
		if (armed) onconfirm(typed);
	}
</script>

<svelte:document {onkeydown} />

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div class="scrim" onclick={(ev) => ev.target === ev.currentTarget && oncancel()}>
	<div
		class="dialog"
		role="alertdialog"
		aria-modal="true"
		aria-label={title ?? 'Confirm action'}
		aria-describedby={`${uid}-msg`}
		bind:this={dialog}
	>
		{#if title}<h2>{title}</h2>{/if}
		<p id={`${uid}-msg`} class:consequence={!!title}>{message}</p>
		<form class="dialog-form" onsubmit={submit}>
			<label>
				<span>Type <code>{expected}</code> to confirm</span>
				<input
					class="input mono-text"
					bind:this={field}
					bind:value={typed}
					type="text"
					name="confirm"
					autocomplete="off"
					spellcheck="false"
					aria-label={`Type ${expected} to confirm`}
				/>
			</label>
			<div class="btn-row">
				<button type="button" class="btn btn-quiet" onclick={oncancel}>Cancel</button>
				<button type="submit" class="btn btn-danger-solid" disabled={!armed}>{action}</button>
			</div>
		</form>
	</div>
</div>
