import { defineConfig } from 'vitest/config';
import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';

// The SPA is compiled to static files and embedded in the Rust binary
// (dec-cryptarch-sveltekit-architecture). It is the whole UI, at the root
// (CRYPTARCH-137); the server keeps /api, /healthz and /metrics.
const BASE = '';

export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			// SPA: one fallback shell for every route. The server sends it for
			// any GET that is not the API, a probe, or a built asset.
			adapter: adapter({ fallback: '200.html' }),
			paths: { base: BASE }
		})
	],
	server: {
		// `npm run dev` against a backend on :8080 (run-dev.sh).
		proxy: {
			'/api': 'http://127.0.0.1:8080'
		}
	},
	test: {
		expect: { requireAssertions: true },
		projects: [
			{
				extends: './vite.config.ts',
				test: {
					name: 'server',
					environment: 'node',
					include: ['src/**/*.{test,spec}.{js,ts}'],
					exclude: ['src/**/*.svelte.{test,spec}.{js,ts}']
				}
			},
			{
				// Components mounted in a DOM, with Svelte's client runtime — the
				// one that enforces things like unique each-block keys.
				extends: './vite.config.ts',
				resolve: { conditions: ['browser'] },
				test: {
					name: 'client',
					environment: 'jsdom',
					include: ['src/**/*.svelte.{test,spec}.{js,ts}']
				}
			}
		]
	}
});
