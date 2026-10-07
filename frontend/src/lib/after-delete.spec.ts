import { describe, expect, it } from 'vitest';
import { afterDelete } from './after-delete.js';
import { takeNotice } from './notice.svelte.js';

describe('afterDelete', () => {
	it('sends a tenant to the dashboard with the notice and the edge warning', () => {
		expect(afterDelete(false, 'Edge sync FAILED', '/dashboard', '/admin/databases')).toBe('/dashboard');
		expect(takeNotice()).toEqual({ message: 'Database deleted.', warning: 'Edge sync FAILED' });
	});

	it('sends an admin to the admin table, saying whether the edge took it', () => {
		expect(afterDelete(true, null, '/dashboard', '/admin/databases')).toBe('/admin/databases');
		expect(takeNotice()).toEqual({ message: 'Database deleted.', warning: null });
		expect(afterDelete(true, 'Edge sync FAILED', '/dashboard', '/admin/databases')).toBe('/admin/databases');
		expect(takeNotice()).toEqual({ message: 'Database deleted.', warning: 'Edge sync FAILED' });
	});
});
