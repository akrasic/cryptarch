import { flushSync, mount, unmount } from 'svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const clip = vi.hoisted(() => ({ copyText: vi.fn(async (_: string) => {}) }));
vi.mock('#lib/clipboard.js', () => clip);
const { default: CopyButton } = await import('./CopyButton.svelte');

let target: HTMLElement;
beforeEach(() => {
	vi.useFakeTimers();
	clip.copyText.mockReset();
	target = document.createElement('div');
	document.body.append(target);
});
afterEach(() => {
	vi.useRealTimers();
	target.remove();
});

const button = () => target.querySelector('button')!;

describe('CopyButton', () => {
	it('copies the text, says so, and settles back', async () => {
		clip.copyText.mockResolvedValue(undefined);
		const app = mount(CopyButton, { target, props: { text: 'postgresql://x', label: 'Copy primary' } });
		flushSync();
		expect([button().textContent?.trim(), button().getAttribute('aria-label')]).toEqual(['Copy', 'Copy primary']);
		button().click();
		await vi.advanceTimersByTimeAsync(0);
		expect(clip.copyText).toHaveBeenCalledWith('postgresql://x');
		expect(button().textContent?.trim()).toBe('Copied');
		expect(button().classList.contains('is-copied')).toBe(true);
		await vi.advanceTimersByTimeAsync(1700);
		expect(button().textContent?.trim()).toBe('Copy');
		expect(button().classList.contains('is-copied')).toBe(false);
		unmount(app);
	});

	it('says to select it by hand when the browser refuses the clipboard', async () => {
		clip.copyText.mockRejectedValue(new Error('denied'));
		const app = mount(CopyButton, { target, props: { text: 'x', label: 'Copy' } });
		flushSync();
		button().click();
		await vi.advanceTimersByTimeAsync(0);
		expect(button().textContent?.trim()).toBe('Select it to copy');
		expect(button().classList.contains('is-failed')).toBe(true);
		expect(button().classList.contains('is-copied')).toBe(false);
		unmount(app);
	});
});
