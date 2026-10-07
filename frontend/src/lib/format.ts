// Human byte sizes, exactly as the server words them: binary units, one decimal, "B" below 1 kB.
//
// In exact integer arithmetic rather than toFixed (CRYPTARCH-141 audit). Rust's
// formatter rounds an exact .x5 tie to EVEN and JS's toFixed rounds it up, so
// 1280 B was "1.2 kB" on the server and "1.3 kB" here — and Postgres sizes are
// multiples of 8 kB pages, so real tables land on such ties.
const UNITS = ['kB', 'MB', 'GB', 'TB', 'PB', 'EB'];

export function humanBytes(bytes: number): string {
	if (bytes < 1024) return `${Math.trunc(bytes)} B`;
	const b = BigInt(Math.trunc(bytes));
	let div = 1024n;
	let unit = 0;
	while (unit < UNITS.length - 1 && b >= div * 1024n) {
		div *= 1024n;
		unit++;
	}
	// Tenths of the unit, rounded half to even.
	let tenths = (b * 10n) / div;
	const twiceRemainder = ((b * 10n) % div) * 2n;
	if (twiceRemainder > div || (twiceRemainder === div && tenths % 2n === 1n)) tenths += 1n;
	return `${tenths / 10n}.${tenths % 10n} ${UNITS[unit]}`;
}
