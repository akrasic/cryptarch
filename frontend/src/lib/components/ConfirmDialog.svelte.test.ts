import { flushSync, mount, unmount } from 'svelte';
import { describe, expect, it, vi } from 'vitest';
import ConfirmDialog from './ConfirmDialog.svelte';

function open() {
	const opener = document.createElement('button');
	document.body.append(opener);
	opener.focus();
	const target = document.createElement('div');
	document.body.append(target);
	const onconfirm = vi.fn();
	const oncancel = vi.fn();
	const app = mount(ConfirmDialog, {
		target,
		props: { message: 'Remove 10.0.0.0/24?', onconfirm, oncancel }
	});
	flushSync();
	const [cancel, confirm] = target.querySelectorAll('button');
	return { app, target, opener, cancel, confirm, onconfirm, oncancel };
}

const key = (k: string) => document.dispatchEvent(new KeyboardEvent('keydown', { key: k }));

describe('ConfirmDialog', () => {
	it('starts on Cancel, so Enter cannot confirm by accident', () => {
		const d = open();
		expect(d.target.textContent).toContain('Remove 10.0.0.0/24?');
		expect(document.activeElement).toBe(d.cancel);
		unmount(d.app);
	});

	it('confirms only from the Confirm button', () => {
		const d = open();
		d.cancel.click();
		expect(d.onconfirm).not.toHaveBeenCalled();
		expect(d.oncancel).toHaveBeenCalledOnce();
		d.confirm.click();
		expect(d.onconfirm).toHaveBeenCalledOnce();
		unmount(d.app);
	});

	it('does not confirm on Enter or any other key', () => {
		const d = open();
		for (const k of ['Enter', ' ', 'y', 'Escape']) key(k);
		expect(d.onconfirm).not.toHaveBeenCalled();
		unmount(d.app);
	});

	it('Escape and the backdrop cancel; a click inside the dialog does not', () => {
		const d = open();
		d.target.querySelector<HTMLElement>('.dialog')!.click();
		expect(d.oncancel).not.toHaveBeenCalled();
		key('Escape');
		expect(d.oncancel).toHaveBeenCalledOnce();
		d.target.querySelector<HTMLElement>('.scrim')!.click();
		expect(d.oncancel).toHaveBeenCalledTimes(2);
		expect(d.onconfirm).not.toHaveBeenCalled();
		unmount(d.app);
	});

	it('keeps Tab between its two buttons and hands focus back on close', () => {
		const d = open();
		key('Tab');
		expect(document.activeElement).toBe(d.confirm);
		key('Tab');
		expect(document.activeElement).toBe(d.cancel);
		unmount(d.app);
		expect(document.activeElement).toBe(d.opener);
	});

	it('is a named modal alert dialog that points at what it says', () => {
		const d = open();
		const dialog = d.target.querySelector('[role=alertdialog]')!;
		expect(dialog.getAttribute('aria-modal')).toBe('true');
		expect(dialog.getAttribute('aria-label')).toBe('Confirm action');
		const msg = document.getElementById(dialog.getAttribute('aria-describedby')!);
		expect(msg?.textContent).toBe('Remove 10.0.0.0/24?');
		unmount(d.app);
	});
});
