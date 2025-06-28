/**
 * Tests for the Vulnerability Dashboard
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { VulnerabilityDashboard } from "../src/assets/ts/VulnerabilityDashboard";
import type { Vulnerability, DashboardConfig } from "../src/assets/ts/types";

// Mock Fuse.js
vi.mock("fuse.js", () => {
  return {
    default: class Fuse {
      constructor(
        public items: any[],
        public options: any
      ) {}
      search(query: string) {
        return this.items
          .filter((item) => JSON.stringify(item).toLowerCase().includes(query.toLowerCase()))
          .map((item) => ({ item }));
      }
    },
  };
});

// Mock fetch
global.fetch = vi.fn();

describe("VulnerabilityDashboard", () => {
  let dashboard: VulnerabilityDashboard;
  let mockConfig: DashboardConfig;
  let mockVulnerabilities: Vulnerability[];

  beforeEach(() => {
    // Setup mock config
    mockConfig = {
      apiEndpoint: "/api/vulns/index.json",
      defaultPageSize: 20,
      searchKeys: ["cveId", "title", "description"],
      severityOrder: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
    };

    // Setup mock vulnerabilities
    mockVulnerabilities = [
      {
        cveId: "CVE-2024-12345",
        title: "Critical RCE in Example Software",
        severity: "CRITICAL",
        cvssScore: 9.8,
        epssScore: 85.5,
        riskScore: 95,
        publishedDate: "2024-01-15T00:00:00Z",
        exploitationStatus: "ACTIVE",
        vendors: ["Example Corp"],
        tags: ["remote", "code-execution"],
      },
      {
        cveId: "CVE-2024-22222",
        title: "SQL Injection in Database Module",
        severity: "HIGH",
        cvssScore: 7.5,
        epssScore: 65.0,
        riskScore: 75,
        publishedDate: "2024-01-14T00:00:00Z",
        exploitationStatus: "POC",
        vendors: ["Database Inc"],
        tags: ["sql-injection", "database"],
      },
      {
        cveId: "CVE-2024-33333",
        title: "Medium Severity XSS",
        severity: "MEDIUM",
        cvssScore: 5.5,
        epssScore: 30.0,
        riskScore: 45,
        publishedDate: "2024-01-13T00:00:00Z",
        exploitationStatus: "NONE",
        vendors: ["Web Corp"],
        tags: ["xss", "web"],
      },
    ];

    // Create dashboard instance
    dashboard = new VulnerabilityDashboard(mockConfig);

    // Reset fetch mock
    (global.fetch as any).mockReset();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("Initialization", () => {
    it("should initialize with default values", () => {
      expect(dashboard.vulnerabilities).toEqual([]);
      expect(dashboard.filteredVulnerabilities).toEqual([]);
      expect(dashboard.currentPage).toBe(1);
      expect(dashboard.pageSize).toBe(20);
      expect(dashboard.sortField).toBe("riskScore");
      expect(dashboard.sortDirection).toBe("desc");
    });

    it("should initialize with empty filters", () => {
      const filters = dashboard.getFilters();
      expect(filters.search).toBe("");
      expect(filters.severity).toBe("");
      expect(filters.cvssMin).toBe(0);
      expect(filters.cvssMax).toBe(10);
      expect(filters.epssMin).toBe(0);
      expect(filters.epssMax).toBe(100);
    });
  });

  describe("Data Loading", () => {
    it("should load vulnerabilities from API", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ vulnerabilities: mockVulnerabilities }),
      });

      await dashboard.loadVulnerabilities();

      expect(global.fetch).toHaveBeenCalledWith("/api/vulns/index.json");
      expect(dashboard.vulnerabilities).toHaveLength(3);
      expect(dashboard.filteredVulnerabilities).toHaveLength(3);
    });

    it("should handle API errors", async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error("Network error"));

      await expect(dashboard.loadVulnerabilities()).rejects.toThrow("Network error");
      expect(dashboard.vulnerabilities).toHaveLength(0);
    });

    it("should handle non-OK responses", async () => {
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: "Not Found",
      });

      await expect(dashboard.loadVulnerabilities()).rejects.toThrow(
        "Failed to load vulnerabilities"
      );
    });
  });

  describe("Filtering", () => {
    beforeEach(async () => {
      dashboard.vulnerabilities = [...mockVulnerabilities];
    });

    it("should filter by search term", () => {
      dashboard.updateFilter("search", "RCE");
      dashboard.applyFilters();

      expect(dashboard.filteredVulnerabilities).toHaveLength(1);
      expect(dashboard.filteredVulnerabilities[0].cveId).toBe("CVE-2024-12345");
    });

    it("should filter by severity", () => {
      dashboard.updateFilter("severity", "CRITICAL");
      dashboard.applyFilters();

      expect(dashboard.filteredVulnerabilities).toHaveLength(1);
      expect(dashboard.filteredVulnerabilities[0].severity).toBe("CRITICAL");
    });

    it("should filter by CVSS range", () => {
      dashboard.updateFilter("cvssMin", 7.0);
      dashboard.updateFilter("cvssMax", 10.0);
      dashboard.applyFilters();

      expect(dashboard.filteredVulnerabilities).toHaveLength(2);
      expect(dashboard.filteredVulnerabilities.every((v) => v.cvssScore >= 7.0)).toBe(true);
    });

    it("should filter by EPSS range", () => {
      dashboard.updateFilter("epssMin", 60);
      dashboard.updateFilter("epssMax", 100);
      dashboard.applyFilters();

      expect(dashboard.filteredVulnerabilities).toHaveLength(2);
      expect(dashboard.filteredVulnerabilities.every((v) => v.epssScore >= 60)).toBe(true);
    });

    it("should filter by exploitation status", () => {
      dashboard.updateFilter("exploitStatus", "ACTIVE");
      dashboard.applyFilters();

      expect(dashboard.filteredVulnerabilities).toHaveLength(1);
      expect(dashboard.filteredVulnerabilities[0].exploitationStatus).toBe("ACTIVE");
    });

    it("should filter by vendor", () => {
      dashboard.updateFilter("vendor", "Database Inc");
      dashboard.applyFilters();

      expect(dashboard.filteredVulnerabilities).toHaveLength(1);
      expect(dashboard.filteredVulnerabilities[0].vendors).toContain("Database Inc");
    });

    it("should filter by tags", () => {
      dashboard.updateFilter("tags", ["sql-injection"]);
      dashboard.applyFilters();

      expect(dashboard.filteredVulnerabilities).toHaveLength(1);
      expect(dashboard.filteredVulnerabilities[0].tags).toContain("sql-injection");
    });

    it("should apply multiple filters", () => {
      dashboard.updateFilter("severity", "HIGH");
      dashboard.updateFilter("epssMin", 50);
      dashboard.applyFilters();

      expect(dashboard.filteredVulnerabilities).toHaveLength(1);
      expect(dashboard.filteredVulnerabilities[0].cveId).toBe("CVE-2024-22222");
    });

    it("should reset filters", () => {
      dashboard.updateFilter("severity", "CRITICAL");
      dashboard.updateFilter("search", "test");
      dashboard.applyFilters();

      dashboard.resetFilters();
      dashboard.applyFilters();

      expect(dashboard.filteredVulnerabilities).toHaveLength(3);
    });
  });

  describe("Sorting", () => {
    beforeEach(() => {
      dashboard.vulnerabilities = [...mockVulnerabilities];
      dashboard.filteredVulnerabilities = [...mockVulnerabilities];
    });

    it("should sort by risk score descending", () => {
      dashboard.sort("riskScore", "desc");

      expect(dashboard.filteredVulnerabilities[0].riskScore).toBe(95);
      expect(dashboard.filteredVulnerabilities[1].riskScore).toBe(75);
      expect(dashboard.filteredVulnerabilities[2].riskScore).toBe(45);
    });

    it("should sort by CVSS score ascending", () => {
      dashboard.sort("cvssScore", "asc");

      expect(dashboard.filteredVulnerabilities[0].cvssScore).toBe(5.5);
      expect(dashboard.filteredVulnerabilities[1].cvssScore).toBe(7.5);
      expect(dashboard.filteredVulnerabilities[2].cvssScore).toBe(9.8);
    });

    it("should sort by severity using custom order", () => {
      dashboard.sort("severity", "desc");

      expect(dashboard.filteredVulnerabilities[0].severity).toBe("CRITICAL");
      expect(dashboard.filteredVulnerabilities[1].severity).toBe("HIGH");
      expect(dashboard.filteredVulnerabilities[2].severity).toBe("MEDIUM");
    });

    it("should sort by date", () => {
      dashboard.sort("publishedDate", "desc");

      expect(dashboard.filteredVulnerabilities[0].cveId).toBe("CVE-2024-12345");
      expect(dashboard.filteredVulnerabilities[1].cveId).toBe("CVE-2024-22222");
      expect(dashboard.filteredVulnerabilities[2].cveId).toBe("CVE-2024-33333");
    });
  });

  describe("Pagination", () => {
    beforeEach(() => {
      // Create 50 vulnerabilities for pagination testing
      dashboard.vulnerabilities = Array.from({ length: 50 }, (_, i) => ({
        cveId: `CVE-2024-${10000 + i}`,
        title: `Vulnerability ${i}`,
        severity: "HIGH",
        cvssScore: 7.5,
        epssScore: 50,
        riskScore: 70,
        publishedDate: "2024-01-01T00:00:00Z",
        exploitationStatus: "NONE",
        vendors: [],
        tags: [],
      }));
      dashboard.filteredVulnerabilities = [...dashboard.vulnerabilities];
    });

    it("should calculate total pages", () => {
      dashboard.pageSize = 10;
      expect(dashboard.getTotalPages()).toBe(5);

      dashboard.pageSize = 20;
      expect(dashboard.getTotalPages()).toBe(3);
    });

    it("should get current page items", () => {
      dashboard.pageSize = 10;
      dashboard.currentPage = 1;

      const items = dashboard.getCurrentPageItems();
      expect(items).toHaveLength(10);
      expect(items[0].cveId).toBe("CVE-2024-10000");
      expect(items[9].cveId).toBe("CVE-2024-10009");
    });

    it("should navigate to next page", () => {
      dashboard.pageSize = 10;
      dashboard.currentPage = 1;

      dashboard.nextPage();
      expect(dashboard.currentPage).toBe(2);

      const items = dashboard.getCurrentPageItems();
      expect(items[0].cveId).toBe("CVE-2024-10010");
    });

    it("should navigate to previous page", () => {
      dashboard.pageSize = 10;
      dashboard.currentPage = 3;

      dashboard.previousPage();
      expect(dashboard.currentPage).toBe(2);
    });

    it("should not go below page 1", () => {
      dashboard.currentPage = 1;
      dashboard.previousPage();
      expect(dashboard.currentPage).toBe(1);
    });

    it("should not exceed total pages", () => {
      dashboard.pageSize = 10;
      dashboard.currentPage = 5;

      dashboard.nextPage();
      expect(dashboard.currentPage).toBe(5);
    });

    it("should reset to page 1 when filters change", () => {
      dashboard.currentPage = 3;
      dashboard.updateFilter("severity", "CRITICAL");
      dashboard.applyFilters();

      expect(dashboard.currentPage).toBe(1);
    });
  });

  describe("URL State Management", () => {
    beforeEach(() => {
      // Clear hash
      window.location.hash = "";
    });

    it("should update URL hash with filters", () => {
      dashboard.updateFilter("search", "test");
      dashboard.updateFilter("severity", "HIGH");
      dashboard.updateFilter("cvssMin", 7.0);
      dashboard.updateURLHash();

      const hash = window.location.hash.slice(1);
      const params = new URLSearchParams(hash);

      expect(params.get("q")).toBe("test");
      expect(params.get("severity")).toBe("HIGH");
      expect(params.get("cvssMin")).toBe("7");
    });

    it("should load filters from URL hash", () => {
      window.location.hash = "q=sql&severity=CRITICAL&epssMin=80&page=2";
      dashboard.loadFromURLHash();

      const filters = dashboard.getFilters();
      expect(filters.search).toBe("sql");
      expect(filters.severity).toBe("CRITICAL");
      expect(filters.epssMin).toBe(80);
      expect(dashboard.currentPage).toBe(2);
    });

    it("should handle invalid URL parameters", () => {
      window.location.hash = "cvssMin=invalid&page=abc";
      dashboard.loadFromURLHash();

      const filters = dashboard.getFilters();
      expect(filters.cvssMin).toBe(0); // Default
      expect(dashboard.currentPage).toBe(1); // Default
    });

    it("should not include default values in hash", () => {
      dashboard.updateFilter("cvssMin", 0);
      dashboard.updateFilter("cvssMax", 10);
      dashboard.updateURLHash();

      const hash = window.location.hash.slice(1);
      expect(hash).toBe("");
    });
  });

  describe("CSV Export", () => {
    beforeEach(() => {
      dashboard.vulnerabilities = [...mockVulnerabilities];
      dashboard.filteredVulnerabilities = [...mockVulnerabilities];
    });

    it("should export all columns", () => {
      const csv = dashboard.exportCSV();
      const lines = csv.split("\n");

      expect(lines[0]).toBe(
        "CVE ID,Title,Severity,CVSS Score,EPSS %,Risk Score,Published Date,Vendors,Tags"
      );
      expect(lines).toHaveLength(4); // Header + 3 vulnerabilities
    });

    it("should escape special characters", () => {
      dashboard.filteredVulnerabilities = [
        {
          cveId: "CVE-2024-99999",
          title: 'Title with, comma and "quotes"',
          severity: "HIGH",
          cvssScore: 7.5,
          epssScore: 50,
          riskScore: 70,
          publishedDate: "2024-01-01T00:00:00Z",
          exploitationStatus: "NONE",
          vendors: ["Vendor, Inc."],
          tags: ["tag1", "tag2"],
        },
      ];

      const csv = dashboard.exportCSV();
      const lines = csv.split("\n");

      expect(lines[1]).toContain('"Title with, comma and ""quotes"""');
      expect(lines[1]).toContain('"Vendor, Inc."');
    });

    it("should export only filtered results", () => {
      dashboard.updateFilter("severity", "CRITICAL");
      dashboard.applyFilters();

      const csv = dashboard.exportCSV();
      const lines = csv.split("\n");

      expect(lines).toHaveLength(2); // Header + 1 vulnerability
      expect(lines[1]).toContain("CVE-2024-12345");
    });

    it("should format dates properly", () => {
      const csv = dashboard.exportCSV();
      const lines = csv.split("\n");

      expect(lines[1]).toContain("2024-01-15");
    });
  });

  describe("Statistics", () => {
    beforeEach(() => {
      dashboard.vulnerabilities = [...mockVulnerabilities];
      dashboard.filteredVulnerabilities = [...mockVulnerabilities];
    });

    it("should calculate severity distribution", () => {
      const stats = dashboard.getStatistics();

      expect(stats.severityDistribution.CRITICAL).toBe(1);
      expect(stats.severityDistribution.HIGH).toBe(1);
      expect(stats.severityDistribution.MEDIUM).toBe(1);
      expect(stats.severityDistribution.LOW).toBe(0);
    });

    it("should calculate average scores", () => {
      const stats = dashboard.getStatistics();

      expect(stats.averageCVSS).toBeCloseTo(7.6, 1);
      expect(stats.averageEPSS).toBeCloseTo(60.2, 1);
      expect(stats.averageRiskScore).toBeCloseTo(71.7, 1);
    });

    it("should count exploitation status", () => {
      const stats = dashboard.getStatistics();

      expect(stats.exploitationCounts.ACTIVE).toBe(1);
      expect(stats.exploitationCounts.POC).toBe(1);
      expect(stats.exploitationCounts.NONE).toBe(1);
    });

    it("should track top vendors", () => {
      const stats = dashboard.getStatistics();

      expect(stats.topVendors).toHaveLength(3);
      expect(stats.topVendors[0]).toEqual({ vendor: "Example Corp", count: 1 });
    });

    it("should track top tags", () => {
      const stats = dashboard.getStatistics();

      const tagNames = stats.topTags.map((t) => t.tag);
      expect(tagNames).toContain("remote");
      expect(tagNames).toContain("sql-injection");

      const remoteTag = stats.topTags.find((t) => t.tag === "remote");
      expect(remoteTag?.count).toBe(1);
    });
  });

  describe("Error Handling", () => {
    it("should handle empty vulnerability list", () => {
      dashboard.vulnerabilities = [];
      dashboard.applyFilters();

      expect(dashboard.filteredVulnerabilities).toHaveLength(0);
      expect(dashboard.getTotalPages()).toBe(1);
      expect(dashboard.getCurrentPageItems()).toHaveLength(0);
    });

    it("should handle invalid sort fields gracefully", () => {
      dashboard.vulnerabilities = [...mockVulnerabilities];
      dashboard.filteredVulnerabilities = [...mockVulnerabilities];
      dashboard.sort("invalidField" as any, "asc");

      // Should not throw and maintain original order
      expect(dashboard.filteredVulnerabilities).toHaveLength(3);
    });

    it("should handle malformed vulnerability data", () => {
      dashboard.vulnerabilities = [
        {
          cveId: "CVE-2024-11111",
          // Missing required fields
        } as any,
      ];
      dashboard.filteredVulnerabilities = [...dashboard.vulnerabilities];

      dashboard.applyFilters();
      // Should handle gracefully
      expect(dashboard.filteredVulnerabilities).toHaveLength(1);
    });
  });
});
