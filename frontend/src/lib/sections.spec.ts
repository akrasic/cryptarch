import { describe, expect, it } from 'vitest';
import { section, sectionFrom, SECTIONS } from './sections';

describe('sections', () => {
	it('reads every known section from an old ?tab= and falls back to connect', () => {
		for (const s of SECTIONS) expect(sectionFrom(s.key)).toBe(s.key);
		expect(sectionFrom(null)).toBe('connect');
		expect(sectionFrom('nonsense')).toBe('connect');
		expect(sectionFrom('CONTENTS')).toBe('connect');
	});

	it('gives every section a title and a line saying what it is for', () => {
		expect(SECTIONS.map((s) => s.key)).toEqual(['connect', 'contents', 'access', 'backups', 'manage']);
		for (const s of SECTIONS) expect(section(s.key).desc.length).toBeGreaterThan(20);
	});
});
