import { flushSync, mount, unmount } from 'svelte';
import { describe, expect, it } from 'vitest';
import StatusBadge, { labelOf, toneOf } from './StatusBadge.svelte';

describe('StatusBadge', () => {
	it('gives each known status its meaning', () => {
		const tones = Object.fromEntries(
			['active', 'ok', 'ready', 'verified', 'recorded', 'running', 'pending', 'restoring', 'deleting',
			 'needs_bootstrap', 'suspended', 'unverified', 'disabled', 'unknown', 'failed', 'unreachable', 'needs_care']
				.map((s) => [s, toneOf(s)])
		);
		expect(tones).toEqual({
			active: 'ok', ok: 'ok', ready: 'ok', verified: 'ok', recorded: 'ok',
			running: 'progress', pending: 'progress', restoring: 'progress',
			// A database still "deleting" is one whose delete failed (repair::FailedDelete).
			deleting: 'danger',
			needs_bootstrap: 'warn', suspended: 'warn', unverified: 'warn',
			disabled: 'neutral', unknown: 'unknown',
			failed: 'danger', unreachable: 'danger', needs_care: 'danger'
		});
	});

	it('shows a status it does not know as danger, never as healthy (CRYPTARCH-81)', () => {
		expect(toneOf('suspended_by_typo')).toBe('danger');
		// Not a property of every object either.
		expect(toneOf('constructor')).toBe('danger');
		expect(toneOf('toString')).toBe('danger');
	});

	it('says the status in words, in sentence case', () => {
		expect(labelOf('needs_bootstrap')).toBe('Needs bootstrap');
		expect(labelOf('active')).toBe('Active');
		expect(labelOf('ok')).toBe('OK');
	});

	it('renders the word with its tone, and a label or title when given', () => {
		const target = document.createElement('div');
		const app = mount(StatusBadge, { target, props: { status: 'needs_care', label: 'Needs care', title: 'why' } });
		flushSync();
		const el = target.querySelector('span')!;
		expect([el.className, el.textContent, el.title]).toEqual(['badge badge-danger', 'Needs care', 'why']);
		unmount(app);
	});
});
