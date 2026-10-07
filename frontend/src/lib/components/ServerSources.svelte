<script lang="ts">
	// The Named sources section: labelled ranges offered on the provision
	// form. Naming one is the admin's approval for tenants to allow it
	// (Security Spine rule 8). Removing one only stops offering it.
	import { tick } from 'svelte';
	import { api } from '#lib/api.js';
	import type { Config } from '#lib/admin-servers.js';
	import ConfirmDialog from './ConfirmDialog.svelte';
	import PageHeader from './PageHeader.svelte';
	import SettingRow from './SettingRow.svelte';

	let { serverId, sources, onchanged }: { serverId: string; sources: Config['sources']; onchanged: () => Promise<void> } =
		$props();
	const base = $derived(`/admin/servers/${encodeURIComponent(serverId)}/sources`);

	let label = $state('');
	let cidr = $state('');
	let isDefault = $state('');
	let removing = $state<Config['sources'][number] | null>(null);
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
			// Gone already: the list on screen is stale.
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
			await api('POST', base, { label, cidr, is_default: isDefault === '1' });
			[label, cidr, isDefault] = ['', '', ''];
		}, 'Named source added.');
	}

	function remove(s: Config['sources'][number]) {
		removing = null;
		run(() => api('DELETE', `${base}/${encodeURIComponent(s.id)}`), `Named source ${s.label} removed.`);
	}
</script>

<PageHeader
	title="Sources"
	desc={`Named ranges users pick from when they provision or allow access ("db network", "LAN") instead of typing addresses. A tenant may allow a range wider than /16 (IPv6: /48) only when it is named here or is the server's default range, and never one reaching 0.0.0.0 or ::, which only an admin can allow. Removing one stops offering it; access already granted stays until revoked per database.`}
/>
{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status" tabindex="-1" bind:this={noticeEl}>{notice}</p>{/if}
<div class="stack-6">
	{#if sources.length === 0}
		<div class="card empty" id="sources-empty">
			<h2>No named sources yet</h2>
			<p>Without one, users type every address themselves, and none wider than /16 (IPv6: /48) unless it is the server's default range.</p>
		</div>
	{:else}
		<div class="card table-wrap">
			<table class="table" id="sources-list">
				<thead><tr><th>Label</th><th>Range</th><th>On the provision form</th><th><span class="sr-only">Actions</span></th></tr></thead>
				<tbody>
					{#each sources as s (s.id)}
						<tr>
							<td>{s.label}</td>
							<td><code>{s.cidr}</code></td>
							<td>
								{#if s.is_default}<span class="badge badge-ok">Pre-ticked</span>{:else}<span class="badge">Opt-in</span>{/if}
							</td>
							<td class="act">
								<button class="btn btn-quiet btn-sm" type="button" disabled={busy} aria-label={`Remove source ${s.label}`}
									onclick={() => (removing = s)}>Remove</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
	<form class="card" onsubmit={add}>
		<div class="card-head"><h2>Add a source</h2></div>
		<SettingRow label="Label" desc={'What users see on the provision form: "LAN", "tailnet".'}>
			<input class="input" type="text" name="source_label" aria-label="Label" placeholder="e.g. LAN" required bind:value={label} />
		</SettingRow>
		<SettingRow label="Range" desc="The IP or CIDR the label stands for.">
			<input class="input mono-text" type="text" name="source_cidr" aria-label="Range" placeholder="e.g. 192.168.8.0/24" autocomplete="off" spellcheck="false" required bind:value={cidr} />
		</SettingRow>
		<SettingRow label="Pre-ticked" desc="A pre-ticked source comes already checked when someone provisions here.">
			<select class="input" name="source_default" aria-label="Pre-ticked" bind:value={isDefault}>
				<option value="">No, opt-in</option>
				<option value="1">Yes, pre-ticked</option>
			</select>
		</SettingRow>
		<div class="card-foot">
			<p class="hint">Offered on the provision form immediately.</p>
			<button class="btn btn-primary" type="submit" disabled={busy}>Add source</button>
		</div>
	</form>
</div>

{#if removing}
	{@const s = removing}
	<ConfirmDialog
		title={`Remove ${s.label} (${s.cidr})?`}
		message="It stops being offered. Access already granted from it stays until revoked per database."
		action="Remove"
		onconfirm={() => remove(s)}
		oncancel={() => (removing = null)}
	/>
{/if}
