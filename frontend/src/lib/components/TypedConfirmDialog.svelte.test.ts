import { flushSync, mount, unmount } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';
import TypedConfirmDialog from './TypedConfirmDialog.svelte';

function open() {
	const opener = document.createElement('button');
	document.body.append(opener);
	opener.focus();
	const target = document.createElement('div');
	document.body.append(target);
	const onconfirm = vi.fn();
	const oncancel = vi.fn();
	const app = mount(TypedConfirmDialog, {
		target,
		props: { message: 'Restore alice_db?', expected: 'alice_db', action: 'Restore', onconfirm, oncancel }
	});
	flushSync();
	const field = target.querySelector<HTMLInputElement>('input[name=confirm]')!;
	const confirm = [...target.querySelectorAll('button')].find((b) => b.textContent === 'Restore')!;
	const type = (v: string) => {
		field.value = v;
		field.dispatchEvent(new Event('input'));
		flushSync();
	};
	const submit = () => target.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
	return { app, target, opener, field, confirm, type, submit, onconfirm, oncancel };
}

afterEach(() => (document.body.innerHTML = ''));

describe('TypedConfirmDialog', () => {
	it('arms only on the exact name, and hands over what was typed', () => {
		const d = open();
		expect(document.activeElement).toBe(d.field);
		for (const wrong of ['', 'alice', 'ALICE_DB', 'alice_db2']) {
			d.type(wrong);
			expect(d.confirm.disabled, wrong).toBe(true);
			d.submit();
		}
		expect(d.onconfirm).not.toHaveBeenCalled();
		d.type(' alice_db ');
		expect(d.confirm.disabled).toBe(false);
		d.submit();
		expect(d.onconfirm).toHaveBeenCalledExactlyOnceWith(' alice_db ');
		unmount(d.app);
	});

	it('cancels on Escape, the backdrop or Cancel, and hands focus back', () => {
		const d = open();
		document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
		d.target.querySelector<HTMLElement>('.scrim')!.click();
		[...d.target.querySelectorAll('button')].find((b) => b.textContent === 'Cancel')!.click();
		expect(d.oncancel).toHaveBeenCalledTimes(3);
		d.target.querySelector<HTMLElement>('.dialog')!.click();
		expect(d.oncancel).toHaveBeenCalledTimes(3);
		unmount(d.app);
		expect(document.activeElement).toBe(d.opener);
	});

	it('is a named modal alert dialog that points at what it says', () => {
		const d = open();
		const dialog = d.target.querySelector('[role=alertdialog]')!;
		expect(dialog.getAttribute('aria-modal')).toBe('true');
		expect(dialog.getAttribute('aria-label')).toBe('Confirm action');
		expect(document.getElementById(dialog.getAttribute('aria-describedby')!)?.textContent).toBe('Restore alice_db?');
		unmount(d.app);
	});

	it('keeps Tab inside: field, Cancel, then the armed button, and round again', () => {
		const d = open();
		const tab = (shiftKey = false) => {
			const ev = new KeyboardEvent('keydown', { key: 'Tab', shiftKey, cancelable: true });
			document.dispatchEvent(ev);
			return ev.defaultPrevented;
		};
		const cancel = [...d.target.querySelectorAll('button')].find((b) => b.textContent === 'Cancel')!;
		expect(document.activeElement).toBe(d.field);
		// Disarmed: the confirm button is not a stop.
		expect(tab()).toBe(true);
		expect(document.activeElement).toBe(cancel);
		tab();
		expect(document.activeElement).toBe(d.field);
		d.type('alice_db');
		tab();
		tab();
		expect(document.activeElement).toBe(d.confirm);
		tab();
		expect(document.activeElement).toBe(d.field);
		tab(true);
		expect(document.activeElement).toBe(d.confirm);
		unmount(d.app);
	});
});
