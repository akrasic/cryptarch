<script lang="ts">
	// Adding a user, and its show-once result: the password is held in
	// this component only, forgotten on pagehide (CRYPTARCH-139) and on leaving.
	import { onMount, tick } from 'svelte';
	import { api } from '#lib/api.js';
	import { quotaChoices, quotaValue } from '#lib/admin.js';
	import ConfirmDialog from './ConfirmDialog.svelte';
	import CopyButton from './CopyButton.svelte';
	import PageHeader from './PageHeader.svelte';
	import SettingRow from './SettingRow.svelte';

	let { usersHref }: { usersHref: string } = $props();

	let username = $state('');
	let password = $state('');
	let quota = $state('5');
	let isAdmin = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);
	let created = $state<{ username: string; password: string; is_admin: boolean } | null>(null);
	let confirmingAdmin = $state(false);
	let onceEl = $state<HTMLElement>();
	let alertEl = $state<HTMLElement>();
	// The form that asked is gone: focus comes to what replaced it.
	$effect(() => {
		if (created) onceEl?.focus();
	});

	onMount(() => {
		// The generated password, and one the admin typed: neither survives
		// into the back/forward cache.
		const forget = () => ([created, password] = [null, '']);
		window.addEventListener('pagehide', forget);
		return () => window.removeEventListener('pagehide', forget);
	});

	function submit(ev: SubmitEvent) {
		ev.preventDefault();
		// An admin cannot be demoted from here: say so before making one.
		if (isAdmin === '1') confirmingAdmin = true;
		else create();
	}

	async function create() {
		confirmingAdmin = false;
		if (busy) return;
		busy = true;
		error = null;
		try {
			created = await api('POST', '/admin/users', {
				username,
				password: password || undefined,
				quota: quotaValue(quota),
				is_admin: isAdmin === '1'
			});
			password = '';
		} catch (e) {
			error = (e as Error).message;
			busy = false;
			// After the admin confirm the dialog has closed: the refusal takes focus.
			await tick();
			alertEl?.focus();
		} finally {
			busy = false;
		}
	}
</script>

{#if created}
	<PageHeader title="User created" desc="Pass these on now. The password is shown once, here, and stored only as a hash." />
	<section class="once" aria-labelledby="created-h" tabindex="-1" bind:this={onceEl}>
		<div class="once-head">
			<h2 id="created-h">Credentials for {created.username}</h2>
			<p>They will be asked to set their own password before they can do anything else.</p>
		</div>
		<dl>
			<dt>Username</dt>
			<dd><code class="well">{created.username}</code><CopyButton text={created.username} label="Copy username" /></dd>
			<dt>Password</dt>
			<dd><code class="well">{created.password}</code><CopyButton text={created.password} label="Copy password" /></dd>
			<dt>Role</dt>
			<dd><span class="setting-value">{created.is_admin ? 'Administrator' : 'User'}</span><span></span></dd>
		</dl>
	</section>
	<div class="btn-row after-once"><a class="btn btn-primary" href={usersHref}>Back to users</a></div>
{:else}
	<PageHeader title="Add user" desc="An account that can sign in and provision databases within its quota." />
	{#if error}<p class="alert alert-danger" role="alert" tabindex="-1" bind:this={alertEl}>{error}</p>{/if}
	<form class="card" onsubmit={submit}>
		<SettingRow label="Username" desc="A lowercase letter first; then lowercase letters, digits, _ and -; 3–32 characters. It cannot be changed later.">
			<input class="input mono-text" type="text" name="username" aria-label="Username" placeholder="e.g. alice" autocomplete="off" spellcheck="false" required bind:value={username} />
		</SettingRow>
		<SettingRow label="Password" desc="Leave empty to generate a strong one, shown once on the next screen. Either way they set their own at first sign-in.">
			<input class="input" type="text" name="password" aria-label="Password" autocomplete="off" placeholder="generated if empty" bind:value={password} />
		</SettingRow>
		<SettingRow label="Database quota" desc="How many databases this user may hold at once.">
			<select class="input" name="quota" aria-label="Quota for the new user" bind:value={quota}>
				{#each quotaChoices(undefined) as c (c.value)}<option value={c.value}>{c.label}</option>{/each}
			</select>
		</SettingRow>
		<SettingRow label="Administrator" desc="Administrators manage users, quotas and servers. Grant it sparingly: an administrator cannot be demoted here, only suspended.">
			<select class="input" name="is_admin" aria-label="Administrator" bind:value={isAdmin}>
				<option value="">No</option>
				<option value="1">Yes</option>
			</select>
		</SettingRow>
		<div class="card-foot">
			<a class="btn btn-quiet" href={usersHref}>Cancel</a>
			<button class="btn btn-primary" type="submit" disabled={busy}>{isAdmin === '1' ? 'Create administrator' : 'Create user'}</button>
		</div>
	</form>
{/if}

{#if confirmingAdmin}
	<ConfirmDialog
		title={`Create ${username} as an administrator?`}
		message="Administrators manage users, quotas and servers, and an administrator cannot be demoted here, only suspended."
		action="Create administrator"
		onconfirm={create}
		oncancel={() => (confirmingAdmin = false)}
	/>
{/if}
