import { describe, expect, it } from 'vitest';
import { setNotice, takeNotice } from './notice.svelte.js';

describe('notice', () => {
	it('is shown once', () => {
		setNotice({ message: 'Database deleted.' });
		expect(takeNotice()).toEqual({ message: 'Database deleted.' });
		expect(takeNotice()).toBeNull();
	});
});
