// Shared admin types, as the API sends them (src/api/admin.rs).
export interface AdminUser {
	id: string;
	username: string;
	is_admin: boolean;
	is_active: boolean;
	/** null = unlimited */
	quota: number | null;
	used: number;
	must_change_password: boolean;
}

export interface UserDb {
	name: string;
	status: string;
	server_name: string;
}

/** The quota choices offered, plus a custom current one. */
export function quotaChoices(current: number | null | undefined): { value: string; label: string }[] {
	const base = [
		{ value: '2', label: '2' },
		{ value: '5', label: '5' },
		{ value: '10', label: '10' },
		{ value: 'unlimited', label: 'unlimited' }
	];
	if (typeof current === 'number' && ![2, 5, 10].includes(current)) {
		base.push({ value: String(current), label: `${current} (current)` });
	}
	return base;
}

/** The dropdown's value as the API's quota: a number, or null for unlimited. */
export function quotaValue(choice: string): number | null {
	return choice === 'unlimited' ? null : Number(choice);
}
