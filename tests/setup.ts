/**
 * Test setup and global mocks
 */

import { vi } from "vitest";
import "@testing-library/jest-dom";

// Mock window.matchMedia
Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: vi.fn().mockImplementation((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(), // deprecated
    removeListener: vi.fn(), // deprecated
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

// Mock IntersectionObserver
global.IntersectionObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}));

// Mock ResizeObserver
global.ResizeObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}));

// Setup global test utilities
global.createMockVulnerability = (overrides = {}) => ({
  cveId: "CVE-2024-12345",
  title: "Test Vulnerability",
  description: "A test vulnerability for unit testing",
  severity: "HIGH",
  cvssScore: 7.5,
  epssScore: 60.0,
  riskScore: 75,
  publishedDate: "2024-01-01T00:00:00Z",
  lastModifiedDate: "2024-01-02T00:00:00Z",
  exploitationStatus: "NONE",
  vendors: ["Test Vendor"],
  products: ["Test Product"],
  tags: ["test"],
  references: [],
  cpeMatches: [],
  attackTechniques: [],
  ...overrides,
});

// Mock console methods to reduce test noise
global.console = {
  ...console,
  error: vi.fn(),
  warn: vi.fn(),
  log: vi.fn(),
};
