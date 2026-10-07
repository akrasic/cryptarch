import { describe, expect, it } from 'vitest';
import { humanBytes } from './format';

// The SAME vector as web::tests::human_bytes_rounds_ties_to_even, so the two
// formatters are held to one answer.
const VECTOR: [number, string][] = [
	[0, '0 B'],
	[1023, '1023 B'],
	[1024, '1.0 kB'],
	[1280, '1.2 kB'],
	[1536, '1.5 kB'],
	[3328, '3.2 kB'],
	[3840, '3.8 kB'],
	[1_310_720, '1.2 MB'],
	[1_200_000, '1.1 MB'],
	[19 * 1024 * 1024, '19.0 MB'],
	[5 * 1024 ** 4, '5.0 TB'],
	[1024 * 1024 - 1, '1024.0 kB']
];

describe('humanBytes', () => {
	it('matches the server-side formatter, ties to even included', () => {
		for (const [bytes, want] of VECTOR) expect(humanBytes(bytes), String(bytes)).toBe(want);
	});
	it('treats negatives as the server does', () => {
		expect(humanBytes(-5)).toBe('-5 B');
	});
});
