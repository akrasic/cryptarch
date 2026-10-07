<script lang="ts">
	// The Listeners section: dial addresses offered with every connection
	// string, besides the advertised one (edited in Settings).
	import { tick } from 'svelte';
	import { api } from '#lib/api.js';
	import type { Config } from '#lib/admin-servers.js';
	import ConfirmDialog from './ConfirmDialog.svelte';
	import PageHeader from './PageHeader.svelte';
	import SettingRow from './SettingRow.svelte';

	let {
		serverId,
		primary,
		listeners,
		onchanged
	}: { serverId: string; primary: string; listeners: Config['listeners']; onchanged: () => Promise<void> } = $props();
	const base = $derived(`/admin/servers/${encodeURIComponent(serverId)}/listeners`);

	let label = $state('');
	let host = $state('');
	let port = $state('');
	let removing = $state<Config['listeners'][number] | null>(null);
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	let alertEl = $state<HTMLElement>();
	let noticeEl = $state<HTMLElement>();

	async function run(what: () => Promise<unknown>, done: string) {
		if (busy) return;
		busy = true;
		error = notice = null;
		try {
			await what();
			notice = done;
			await onchanged();
		} catch (e) {
			error = (e as Error).message;
			if ((e as { code?: string }).code === 'no_such_item') await onchanged();
		} finally {
			busy = false;
		}
		// The button that asked was disabled meanwhile, or its row is gone:
		// focus goes to what happened, not to the page.
		await tick();
		(error ? alertEl : noticeEl)?.focus();
	}

	function add(ev: SubmitEvent) {
		ev.preventDefault();
		run(async () => {
			await api('POST', base, { label, host, port: Number(port) });
			[label, host, port] = ['', '', ''];
		}, 'Listener added.');
	}

	function remove(l: Config['listeners'][number]) {
		removing = null;
		run(() => api('DELETE', `${base}/${encodeURIComponent(l.id)}`), `Listener ${l.label} removed.`);
	}
</script>

<PageHeader
	title="Listeners"
	desc={'Addresses users dial, each shown as its own connection string: the primary (the advertised address in Settings) and any added here. Listeners are where users dial to; "Allowed from" is where they come from. Names welcome.'}
/>
{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status" tabindex="-1" bind:this={noticeEl}>{notice}</p>{/if}
<div class="stack-6">
	<div class="card table-wrap">
		<table class="table" id="listeners-list">
			<thead><tr><th>Label</th><th>Address</th><th><span class="sr-only">Actions</span></th></tr></thead>
			<tbody>
				<tr>
					<td>primary</td>
					<td><code>{primary}</code></td>
					<td class="act sub">Edit in Settings</td>
				</tr>
				{#each listeners as l (l.id)}
					<tr>
						<td>{l.label}</td>
						<td><code>{l.host}:{l.port}</code></td>
						<td class="act">
							<button class="btn btn-quiet btn-sm" type="button" disabled={busy} aria-label={`Remove listener ${l.label}`}
								onclick={() => (removing = l)}>Remove</button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<form class="card" onsubmit={add}>
		<div class="card-head"><h2>Add a listener</h2></div>
		<SettingRow label="Label" desc="How this address is titled next to its connection string.">
			<input class="input" type="text" name="listener_label" aria-label="Label" placeholder="e.g. lan, tailnet" required bind:value={label} />
		</SettingRow>
		<SettingRow label="Host" desc="The IP or name users dial.">
			<input class="input mono-text" type="text" name="listener_host" aria-label="Host" placeholder="e.g. 192.168.8.14" spellcheck="false" required bind:value={host} />
		</SettingRow>
		<SettingRow label="Port" desc="Usually the bouncer's published port.">
			<input class="input mono-text" type="number" name="listener_port" aria-label="Port" placeholder="6432" min="1" max="65535" required bind:value={port} />
		</SettingRow>
		<div class="card-foot">
			<p class="hint">Offered with every connection string from now on.</p>
			<button class="btn btn-primary" type="submit" disabled={busy}>Add listener</button>
		</div>
	</form>
</div>

{#if removing}
	{@const l = removing}
	<ConfirmDialog
		title={`Remove ${l.label} (${l.host}:${l.port})?`}
		message="Its connection strings stop being offered. Anything already using that address keeps working until it changes."
		action="Remove"
		onconfirm={() => remove(l)}
		oncancel={() => (removing = null)}
	/>
{/if}
