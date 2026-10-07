<script lang="ts">
	// One user's admin page. Quota, suspend/enable and reset for another user; a
	// reset's password is shown once, in place, and forgotten on Done or
	// pagehide. Your own account is managed in Profile instead.
	import { onMount, tick } from 'svelte';
	import { api } from '#lib/api.js';
	import { quotaChoices, quotaValue, type AdminUser, type UserDb } from '#lib/admin.js';
	import ConfirmDialog from './ConfirmDialog.svelte';
	import CopyButton from './CopyButton.svelte';
	import PageHeader from './PageHeader.svelte';
	import SettingRow from './SettingRow.svelte';
	import StatusBadge from './StatusBadge.svelte';

	let {
		user,
		isSelf,
		databases,
		onchanged,
		profileHref,
		dbHref
	}: {
		user: AdminUser;
		isSelf: boolean;
		databases: UserDb[];
		/** Re-read the page's data after a change. */
		onchanged: () => Promise<void>;
		profileHref: string;
		dbHref: (name: string) => string;
	} = $props();

	const path = $derived(`/admin/users/${encodeURIComponent(user.id)}`);
	let quota = $state('');
	$effect.pre(() => {
		quota = user.quota === null ? 'unlimited' : String(user.quota);
	});
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);
	let confirming = $state<'suspend' | 'reset' | null>(null);
	let reset = $state<{ username: string; password: string } | null>(null);
	let alertEl = $state<HTMLElement>();
	let noticeEl = $state<HTMLElement>();
	let onceEl = $state<HTMLElement>();

	// After a dialog's request the button that opened it was disabled, or is
	// gone: focus goes to what happened instead of falling to the page.
	async function land(on: () => HTMLElement | undefined) {
		await tick();
		on()?.focus();
	}

	onMount(() => {
		const forget = () => (reset = null);
		window.addEventListener('pagehide', forget);
		return () => window.removeEventListener('pagehide', forget);
	});

	async function act(run: () => Promise<unknown>, done: string) {
		if (busy) return;
		busy = true;
		error = notice = null;
		try {
			await run();
			notice = done;
			await onchanged();
			busy = false;
			await land(() => noticeEl);
		} catch (e) {
			error = (e as Error).message;
			busy = false;
			await land(() => alertEl);
		} finally {
			busy = false;
		}
	}

	const saveQuota = (ev: SubmitEvent) => {
		ev.preventDefault();
		return act(() => api('POST', `${path}/quota`, { quota: quotaValue(quota) }), 'Quota updated.');
	};
	const setActive = (active: boolean) => {
		confirming = null;
		return act(
			() => api('POST', `${path}/active`, { active }),
			active ? 'Account enabled.' : 'Account suspended — their sessions were signed out.'
		);
	};
	async function doReset() {
		confirming = null;
		if (busy) return;
		busy = true;
		error = notice = null;
		try {
			reset = await api('POST', `${path}/reset-password`);
			busy = false;
			await land(() => onceEl);
		} catch (e) {
			error = (e as Error).message;
			busy = false;
			await land(() => alertEl);
		} finally {
			busy = false;
		}
	}
</script>

<PageHeader
	title={user.username}
	desc={isSelf
		? 'This is you. Your own password and sessions are managed in Profile.'
		: "Their quota, whether they can sign in, and the databases they hold."}
/>
{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status" tabindex="-1" bind:this={noticeEl}>{notice}</p>{/if}

{#if reset}
	<section class="once" aria-labelledby="reset-h" tabindex="-1" bind:this={onceEl}>
		<div class="once-head">
			<h2 id="reset-h">New password for {reset.username}</h2>
			<p>Shown once: pass it on now. All their sessions were signed out, and they set their own at next sign-in.</p>
		</div>
		<dl>
			<dt>Username</dt>
			<dd><code class="well">{reset.username}</code><span></span></dd>
			<dt>Password</dt>
			<dd><code class="well">{reset.password}</code><CopyButton text={reset.password} label="Copy password" /></dd>
		</dl>
	</section>
	<div class="btn-row after-once">
		<button class="btn btn-primary" type="button" onclick={() => (reset = null)}>Done — I've passed it on</button>
	</div>
{:else}
	<div class="stack-6">
		<div class="card">
			<SettingRow label="Role" desc={user.is_admin ? 'Manages users, quotas and servers.' : 'Manages their own databases, within their quota.'}>
				<span class="setting-value">{user.is_admin ? 'Administrator' : 'User'}</span>
			</SettingRow>
			<SettingRow label="Status" desc={user.is_active ? 'Can sign in.' : 'Cannot sign in; their databases keep running.'}>
				<StatusBadge status={user.is_active ? 'active' : 'suspended'} />
			</SettingRow>
			<SettingRow label="Databases" desc="Held now, of what their quota allows.">
				<span class="setting-value">{user.used} of {user.quota ?? 'unlimited'}</span>
			</SettingRow>
		</div>

		<form class="card" onsubmit={saveQuota}>
			<SettingRow
				label="Database quota"
				desc="How many databases this user may hold at once. Lowering it never deletes anything: it only blocks new provisioning past the cap."
			>
				<select class="input" name="quota" aria-label={`Quota for ${user.username}`} bind:value={quota}>
					{#each quotaChoices(user.quota) as c (c.value)}<option value={c.value}>{c.label}</option>{/each}
				</select>
			</SettingRow>
			<div class="card-foot">
				<p class="hint">Takes effect on their next provision attempt.</p>
				<button class="btn btn-primary" type="submit" disabled={busy}>Save</button>
			</div>
		</form>

		{#if isSelf}
			<p class="alert" id="self-note">
				<strong>That's you.</strong> Your own password and sessions live in <a href={profileHref}>Profile</a>. This
				page is for other accounts, so you cannot suspend yourself out of the building.
			</p>
		{:else}
			<div class="card">
				<SettingRow
					label={user.is_active ? 'Suspend account' : 'Enable account'}
					desc={user.is_active
						? 'Blocks sign-in and signs out every session immediately. Their databases keep running and stay reachable by anything holding their connection string: delete a database to stop it.'
						: 'Restores sign-in. Their databases are untouched by this.'}
				>
					{#if user.is_active}
						<button class="btn btn-danger" type="button" disabled={busy} onclick={() => (confirming = 'suspend')}>Suspend…</button>
					{:else}
						<button class="btn" type="button" disabled={busy} onclick={() => setActive(true)}>Enable</button>
					{/if}
				</SettingRow>
				<SettingRow label="Reset password" desc="Generates a new password, shown once. Every session they have is signed out.">
					<button class="btn" type="button" disabled={busy} onclick={() => (confirming = 'reset')}>Reset password…</button>
				</SettingRow>
			</div>
		{/if}

		<div>
			<h2 class="section-title first">Databases</h2>
			{#if databases.length === 0}
				<div class="card empty" id="user-no-databases">
					<h3>None yet</h3>
					<p>They have not provisioned a database.</p>
				</div>
			{:else}
				<div class="card table-wrap">
					<table class="table" id="user-databases">
						<thead><tr><th>Database</th><th>Server</th><th>Status</th></tr></thead>
						<tbody>
							{#each databases as d (d.name)}
								<tr>
									<td><a class="row-link" href={dbHref(d.name)}>{d.name}</a></td>
									<td class="sub">{d.server_name}</td>
									<td><StatusBadge status={d.status} /></td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>
	</div>
{/if}

{#if confirming === 'suspend'}
	<ConfirmDialog
		title={`Suspend ${user.username}?`}
		message="They cannot sign in, and every session they have is signed out immediately. Their databases keep running."
		action="Suspend"
		onconfirm={() => setActive(false)}
		oncancel={() => (confirming = null)}
	/>
{:else if confirming === 'reset'}
	<ConfirmDialog
		title={`Reset ${user.username}'s password?`}
		message="A new password is shown once, here. Every session they have is signed out."
		action="Reset password"
		onconfirm={doReset}
		oncancel={() => (confirming = null)}
	/>
{/if}
