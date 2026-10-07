import { describe, expect, it } from 'vitest';
import { edgeNote, type EdgeOutcome } from './admin-servers.js';

const edge = (state: EdgeOutcome['state'], error: string | null = null): EdgeOutcome => ({ state, rules: 2, hba: null, knobs: null, error });

describe('edgeNote', () => {
	it('words each outcome, and a failed sync as a failure', () => {
		expect(edgeNote('Pooling saved', edge('applied'))).toEqual({ failed: false, text: 'Pooling saved — edge synced.' });
		expect(edgeNote('Pooling saved', edge('manual')).text).toContain('manual placement');
		expect(edgeNote('Pooling saved', edge('failed', 'RELOAD refused'))).toEqual({
			failed: true,
			text: 'Pooling saved, but edge sync FAILED: RELOAD refused'
		});
		expect(edgeNote('x', edge('mystery' as 'applied')).failed).toBe(true);
	});
});
