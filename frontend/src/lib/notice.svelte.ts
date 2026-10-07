// One message for the next page to show — a flash, without a
// ?ok= flash codes, so a delete can land on the dashboard and say what
// happened. Read once: the page that takes it clears it. Never anything
// secret; this outlives the page that set it.

export interface Notice {
	message: string;
	/** An edge that did not take the change rides along, shown as an alert. */
	warning?: string | null;
}

let pending = $state<Notice | null>(null);

export function setNotice(n: Notice) {
	pending = n;
}

export function takeNotice(): Notice | null {
	const n = pending;
	pending = null;
	return n;
}
