import { describe, expect, it } from 'vitest';
import { quotaChoices, quotaValue } from './admin.js';

describe('quota choices', () => {
	it('keeps a custom current value instead of silently reassigning it to a preset', () => {
		expect(quotaChoices(7).map((c) => c.value)).toEqual(['2', '5', '10', 'unlimited', '7']);
		expect(quotaChoices(5).map((c) => c.value)).toEqual(['2', '5', '10', 'unlimited']);
		expect(quotaChoices(null).map((c) => c.value)).toEqual(['2', '5', '10', 'unlimited']);
	});
	it('sends unlimited as null and the rest as numbers', () => {
		expect(quotaValue('unlimited')).toBeNull();
		expect(quotaValue('10')).toBe(10);
	});
});
