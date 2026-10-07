<script lang="ts">
	// The design system (tokens and shell, then its components) and the mount
	// point's own styles. No inline styles anywhere: the CSP is
	// style-src 'self'.
	import '../keyring.css';
	import '../components.css';
	import '../app-shell.css';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();
</script>

{@render children()}
