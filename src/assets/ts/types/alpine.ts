/**
 * Alpine.js type extensions
 */

declare global {
  interface Window {
    Alpine: import("alpinejs").Alpine;
    Fuse: typeof import("fuse.js").default;
  }
}

export {};
