import { describe, expect, it } from 'vitest';
import {
	allowedFromAfterSwitch,
	defaultSourceIds,
	initialAllowedFrom,
	type ServerOption
} from './provision';

const plain = (id: string, cidr: string | null): ServerOption => ({
	id,
	name: id,
	engine: 'postgres',
	default_cidr: cidr,
	sources: []
});
const named: ServerOption = {
	id: 'n',
	name: 'n',
	engine: 'postgres',
	default_cidr: '10.9.0.0/16',
	sources: [
		{ id: 's1', label: 'db network', cidr: '172.18.0.0/16', is_default: true },
		{ id: 's2', label: 'LAN', cidr: '192.168.8.0/24', is_default: false }
	]
};

describe('provision form', () => {
	it('prefills the default range only for servers without named sources', () => {
		expect(initialAllowedFrom(plain('a', '10.0.0.0/24'))).toBe('10.0.0.0/24');
		expect(initialAllowedFrom(named)).toBe('');
		expect(initialAllowedFrom(plain('b', null))).toBe('');
		expect(initialAllowedFrom(undefined)).toBe('');
	});

	it('follows the server while the field still holds the old default', () => {
		const a = plain('a', '10.0.0.0/24');
		const b = plain('b', '10.1.0.0/24');
		expect(allowedFromAfterSwitch('10.0.0.0/24', a, b)).toBe('10.1.0.0/24');
		expect(allowedFromAfterSwitch(' 10.0.0.0/24 ', a, b)).toBe('10.1.0.0/24');
	});

	it('never overwrites what the user typed', () => {
		const a = plain('a', '10.0.0.0/24');
		const b = plain('b', '10.1.0.0/24');
		expect(allowedFromAfterSwitch('10.0.0.0/24, 10.5.5.5', a, b)).toBe('10.0.0.0/24, 10.5.5.5');
		expect(allowedFromAfterSwitch('', a, b)).toBe('');
	});

	it('ticks only the selected server’s default sources', () => {
		expect(defaultSourceIds(named)).toEqual(['s1']);
		expect(defaultSourceIds(plain('a', null))).toEqual([]);
		expect(defaultSourceIds(undefined)).toEqual([]);
	});
});
