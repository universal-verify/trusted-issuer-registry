import type { RegistrySnapshot } from './index.js';

declare const snapshot: RegistrySnapshot & { version: string };
export default snapshot;
