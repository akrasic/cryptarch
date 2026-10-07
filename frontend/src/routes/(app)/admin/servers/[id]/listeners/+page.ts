import { loadConfig } from '../config.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, params }) => ({ config: await loadConfig(fetch, params.id) });
