/**
 * Alpine.js type extensions
 */

import type { CveModal } from "../components/CveModal";

declare global {
  interface Window {
    Alpine: import("alpinejs").Alpine;
    Fuse: typeof import("fuse.js").default;
    cveModal: CveModal;
  }
}

export {};
