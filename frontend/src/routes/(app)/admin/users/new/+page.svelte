<script lang="ts">
	import { resolve } from '$app/paths';
	import AdminNewUser from '#lib/components/AdminNewUser.svelte';
</script>

<svelte:head><title>Add user · Admin — Cryptarch</title></svelte:head>

<AdminNewUser usersHref={resolve('/(app)/admin/users')} />
