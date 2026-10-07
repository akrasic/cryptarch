import { flushSync, mount, unmount } from 'svelte';
import { describe, expect, it } from 'vitest';
import AdminDatabases, { type FleetDb } from './AdminDatabases.svelte';

const db = (name: string, last_backup: FleetDb['last_backup']): FleetDb => ({ name, status: 'active', owner: 'alice', server_name: 'local', last_backup });

describe('AdminDatabases', () => {
	it('says never, marks an unread ok backup, and links each database', () => {
		const target = document.createElement('div');
		const app = mount(AdminDatabases, {
			target,
			props: {
				databases: [
					db('nobackup_db', null),
					db('unread_db', { at: '2026-10-07T09:00:00Z', status: 'ok', verified: false }),
					db('read_db', { at: '2026-10-07T09:00:00Z', status: 'ok', verified: true }),
					db('failed_db', { at: '2026-10-07T09:00:00Z', status: 'failed', verified: false })
				],
				dbHref: (n: string) => `/db/${n}`
			}
		});
		flushSync();
		// Lowercased: badges say their word in sentence case.
		const rows = [...target.querySelectorAll('tbody tr')].map((r) => (r.textContent ?? '').toLowerCase());
		// The cell itself, not the row: a row named "never…" would pass for free.
		const lastCell = (i: number) => target.querySelectorAll('tbody tr')[i].querySelectorAll('td')[4].textContent?.trim();
		expect(lastCell(0)).toBe('Never');
		expect(rows[1]).toContain('unverified');
		expect(rows[2]).not.toContain('unverified');
		expect(rows[2]).toContain('2026-10-07 09:00 utc');
		expect(rows[3]).toContain('failed');
		expect(rows[3]).not.toContain('unverified');
		expect(target.querySelector('a[href="/db/read_db"]')).not.toBeNull();
		unmount(app);
	});
});
