// Where a delete lands, and what it says there (CRYPTARCH-143). A tenant goes
// back to their dashboard, an admin to the admin databases table; either way
// with a notice, and an edge that did not take the delete said too — the
// admin is the one who has to sync it.
import { setNotice } from './notice.svelte.js';

export function afterDelete(isAdmin: boolean, warning: string | null, dashboard: string, adminDatabases: string): string {
	setNotice({ message: 'Database deleted.', warning });
	return isAdmin ? adminDatabases : dashboard;
}
