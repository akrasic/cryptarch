<script lang="ts">
	// Your profile: who you are, changing your password, your sessions
	// (CRYPTARCH-133). A session whose password an admin set is sent here and
	// can do nothing else until it sets its own (CRYPTARCH-146).
	import { onMount } from 'svelte';
	import { api, type Me } from '#lib/api.js';
	import PageHeader from './PageHeader.svelte';
	import SettingRow from './SettingRow.svelte';
	import StatusBadge from './StatusBadge.svelte';

	interface MySession {
		created_at: string;
		last_seen: string;
		current: boolean;
	}

	let { me, onchanged }: { me: Me; onchanged: () => Promise<void> } = $props();

	let sessions = $state<MySession[]>([]);
	let current = $state('');
	let next = $state('');
	let confirm = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);

	async function loadSessions() {
		try {
			sessions = (await api<{ sessions: MySession[] }>('GET', '/me/sessions')).sessions;
		} catch (e) {
			error = (e as Error).message;
		}
	}
	onMount(() => {
		loadSessions();
		// Typed passwords, kept across a refused change so it can be
		// corrected: never into the back/forward cache (final audit P2).
		const forget = () => ([current, next, confirm] = ['', '', '']);
		window.addEventListener('pagehide', forget);
		return () => window.removeEventListener('pagehide', forget);
	});

	async function change(ev: SubmitEvent) {
		ev.preventDefault();
		if (busy) return;
		busy = true;
		error = notice = null;
		try {
			await api('POST', '/me/password', {
				current_password: current,
				new_password: next,
				confirm_password: confirm
			});
			[current, next, confirm] = ['', '', ''];
			notice = 'Password changed. All other sessions were signed out.';
			// The gate (if any) lifts; the session list is down to this one.
			await Promise.all([onchanged(), loadSessions()]);
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}

	async function revokeOthers() {
		busy = true;
		error = notice = null;
		try {
			const r = await api<{ signed_out: number }>('POST', '/me/sessions/revoke-others');
			notice = `Signed out ${r.signed_out} other session(s).`;
			await loadSessions();
		} catch (e) {
			error = (e as Error).message;
		} finally {
			busy = false;
		}
	}

	const when = (iso: string) => iso.slice(0, 16).replace('T', ' ') + ' UTC';
</script>

<PageHeader title="Profile" desc="Your account: its password, and every place you are signed in." />
{#if me.must_change_password}
	<p class="alert alert-warn" role="alert">
		<strong>Your password was set by an administrator.</strong> Set your own below before doing anything
		else: until then, nothing but this page is open to you.
	</p>
{/if}
{#if error}<p class="alert alert-danger" role="alert">{error}</p>{/if}
{#if notice}<p class="alert alert-ok" role="status">{notice}</p>{/if}

<div class="card">
	<SettingRow label="Username" desc="How you sign in. It cannot be changed.">
		<span class="setting-value">{me.username}</span>
	</SettingRow>
	<SettingRow
		label="Role"
		desc={me.is_admin
			? 'You manage users, quotas and servers, as well as your own databases.'
			: 'You manage your own databases, within your quota.'}
	>
		<span class="setting-value">{me.is_admin ? 'Administrator' : 'User'}</span>
	</SettingRow>
</div>

<h2 class="section-title">Change password</h2>
<form class="card" onsubmit={change}>
	<SettingRow
		label="Current password"
		desc="Required even while signed in: proof it's really you at the keyboard."
	>
		<input
			class="input"
			type="password"
			name="current_password"
			aria-label="Current password"
			autocomplete="current-password"
			required
			bind:value={current}
		/>
	</SettingRow>
	<SettingRow label="New password" desc="At least 8 characters.">
		<input
			class="input"
			type="password"
			name="new_password"
			aria-label="New password"
			autocomplete="new-password"
			required
			bind:value={next}
		/>
	</SettingRow>
	<SettingRow label="Confirm new password" desc="Typed twice so a typo can't lock you out.">
		<input
			class="input"
			type="password"
			name="confirm_password"
			aria-label="Confirm new password"
			autocomplete="new-password"
			required
			bind:value={confirm}
		/>
	</SettingRow>
	<div class="card-foot">
		<p class="hint">Signs out every other session automatically.</p>
		<button class="btn btn-primary" type="submit" disabled={busy}>Change password</button>
	</div>
</form>

<h2 class="section-title">Where you're signed in</h2>
{#if sessions.length > 0}
	<p class="section-desc" id="session-count">
		{sessions.length === 1
			? 'Only here.'
			: `${sessions.length} sessions, this one included. One you do not recognise is a reason to change your password.`}
	</p>
{/if}
<div class="card">
	<div class="table-wrap">
		<table class="table" id="sessions">
			<thead><tr><th>Started</th><th>Last seen</th></tr></thead>
			<tbody>
				{#each sessions as s, i (i)}
					<!-- The mark sits in the first cell: on a phone the table scrolls,
					     and the one row that is yours must not be the part cut off. -->
					<tr>
						<td class="when">
							{when(s.created_at)}
							{#if s.current}<StatusBadge status="active" label="This session" />{/if}
						</td>
						<td class="when">{when(s.last_seen)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	{#if sessions.length > 1}
		<div class="card-foot">
			<p class="hint">Ends every session but this one, wherever it is.</p>
			<button class="btn" type="button" disabled={busy} onclick={revokeOthers}>Sign out everywhere else</button>
		</div>
	{/if}
</div>
