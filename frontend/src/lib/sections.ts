// A database's sections, in sidebar order. Each is its own page under
// /db/[name]/ (CRYPTARCH-152); the title is the page's h1 and the sidebar's
// label, the description the line under it.
export const SECTIONS = [
	{
		key: 'connect',
		title: 'Connect',
		desc: 'One address per place you connect from: inside the stack, this machine, another box on the network. Same database and credentials; only the address differs.'
	},
	{ key: 'contents', title: 'Contents', desc: 'What is in this database right now, read live from its server.' },
	{
		key: 'access',
		title: 'Access',
		desc: 'The networks that can reach this database through the bouncer. With none, nothing can connect: the edge refuses by default.'
	},
	{
		key: 'backups',
		title: 'Backups',
		desc: "Full copies of this database, compressed and encrypted on the server's backup disk. Restoring one replaces everything in the database."
	},
	{ key: 'manage', title: 'Manage', desc: 'Reset the password, or delete the database.' }
] as const;

export type SectionKey = (typeof SECTIONS)[number]['key'];

export function section(key: SectionKey) {
	return SECTIONS.find((s) => s.key === key)!;
}

/** The section an old `?tab=` link names; anything unknown is Connect. */
export function sectionFrom(value: string | null): SectionKey {
	return SECTIONS.find((s) => s.key === value)?.key ?? 'connect';
}
