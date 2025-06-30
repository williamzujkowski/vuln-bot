/**
 * Saved Searches and Smart Suggestions Component
 * Provides saved search functionality and intelligent search suggestions
 */

export interface SavedSearch {
  id: string;
  name: string;
  query: string;
  filters: Record<string, any>;
  timestamp: number;
  count?: number;
}

export interface SearchSuggestion {
  text: string;
  type: "recent" | "vendor" | "cve" | "tag" | "smart";
  weight: number;
  metadata?: Record<string, any>;
}

export class SavedSearches {
  private storageKey = "vuln_saved_searches";
  private recentSearchesKey = "vuln_recent_searches";
  private maxSavedSearches = 20;
  private maxRecentSearches = 10;
  private maxSuggestions = 8;

  constructor() {
    this.init();
  }

  private init(): void {
    // Clean up old searches periodically
    this.cleanupOldSearches();
  }

  /**
   * Save a search with current filters
   */
  saveSearch(name: string, query: string, filters: Record<string, any>): SavedSearch {
    const searches = this.getSavedSearches();

    const newSearch: SavedSearch = {
      id: this.generateId(),
      name,
      query,
      filters: { ...filters },
      timestamp: Date.now(),
    };

    // Remove existing search with same name
    const filtered = searches.filter((s) => s.name !== name);

    // Add new search at beginning
    filtered.unshift(newSearch);

    // Keep only max searches
    const trimmed = filtered.slice(0, this.maxSavedSearches);

    this.storeSavedSearches(trimmed);
    return newSearch;
  }

  /**
   * Get all saved searches
   */
  getSavedSearches(): SavedSearch[] {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (error) {
      console.warn("Failed to load saved searches:", error);
    }
    return [];
  }

  /**
   * Delete a saved search
   */
  deleteSavedSearch(id: string): void {
    const searches = this.getSavedSearches();
    const filtered = searches.filter((s) => s.id !== id);
    this.storeSavedSearches(filtered);
  }

  /**
   * Update search count (for analytics)
   */
  updateSearchCount(id: string, count: number): void {
    const searches = this.getSavedSearches();
    const search = searches.find((s) => s.id === id);
    if (search) {
      search.count = count;
      this.storeSavedSearches(searches);
    }
  }

  /**
   * Add to recent searches
   */
  addRecentSearch(query: string): void {
    if (!query.trim()) return;

    const recent = this.getRecentSearches();

    // Remove if already exists
    const filtered = recent.filter((q) => q !== query);

    // Add at beginning
    filtered.unshift(query);

    // Keep only max recent
    const trimmed = filtered.slice(0, this.maxRecentSearches);

    this.storeRecentSearches(trimmed);
  }

  /**
   * Get recent searches
   */
  getRecentSearches(): string[] {
    try {
      const stored = localStorage.getItem(this.recentSearchesKey);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (error) {
      console.warn("Failed to load recent searches:", error);
    }
    return [];
  }

  /**
   * Generate search suggestions based on input
   */
  generateSuggestions(input: string, vulnerabilities: any[]): SearchSuggestion[] {
    const suggestions: SearchSuggestion[] = [];
    const inputLower = input.toLowerCase().trim();

    if (inputLower.length < 2) {
      // Show recent searches when input is short
      const recent = this.getRecentSearches();
      recent.forEach((query, index) => {
        suggestions.push({
          text: query,
          type: "recent",
          weight: 100 - index * 10,
        });
      });
      return suggestions.slice(0, this.maxSuggestions);
    }

    // CVE ID suggestions
    if (inputLower.startsWith("cve-") || /^\d{4}/.test(inputLower)) {
      vulnerabilities.forEach((vuln) => {
        if (vuln.cveId.toLowerCase().includes(inputLower)) {
          suggestions.push({
            text: vuln.cveId,
            type: "cve",
            weight: 90,
            metadata: { title: vuln.title },
          });
        }
      });
    }

    // Vendor suggestions
    const vendors = new Set<string>();
    vulnerabilities.forEach((vuln) => {
      vuln.vendors?.forEach((vendor: string) => {
        if (vendor.toLowerCase().includes(inputLower)) {
          vendors.add(vendor);
        }
      });
    });

    vendors.forEach((vendor) => {
      suggestions.push({
        text: vendor,
        type: "vendor",
        weight: 80,
      });
    });

    // Tag suggestions
    const tags = new Set<string>();
    vulnerabilities.forEach((vuln) => {
      vuln.tags?.forEach((tag: string) => {
        if (tag.toLowerCase().includes(inputLower)) {
          tags.add(tag);
        }
      });
    });

    tags.forEach((tag) => {
      suggestions.push({
        text: tag,
        type: "tag",
        weight: 70,
      });
    });

    // Smart suggestions based on common patterns
    this.addSmartSuggestions(inputLower, suggestions);

    // Recent search suggestions that match input
    const recent = this.getRecentSearches();
    recent.forEach((query, index) => {
      if (query.toLowerCase().includes(inputLower)) {
        suggestions.push({
          text: query,
          type: "recent",
          weight: 60 - index * 5,
        });
      }
    });

    // Sort by weight and remove duplicates
    const unique = new Map<string, SearchSuggestion>();
    suggestions.forEach((suggestion) => {
      const existing = unique.get(suggestion.text);
      if (!existing || existing.weight < suggestion.weight) {
        unique.set(suggestion.text, suggestion);
      }
    });

    return Array.from(unique.values())
      .sort((a, b) => b.weight - a.weight)
      .slice(0, this.maxSuggestions);
  }

  /**
   * Add smart suggestions based on patterns
   */
  private addSmartSuggestions(input: string, suggestions: SearchSuggestion[]): void {
    const smartPatterns = [
      { pattern: /buffer.?overflow/i, suggestion: "buffer overflow", weight: 85 },
      { pattern: /sql.?injection/i, suggestion: "sql injection", weight: 85 },
      { pattern: /cross.?site/i, suggestion: "cross-site scripting", weight: 85 },
      { pattern: /remote.?code/i, suggestion: "remote code execution", weight: 85 },
      { pattern: /privilege.?escalation/i, suggestion: "privilege escalation", weight: 85 },
      { pattern: /denial.?of.?service/i, suggestion: "denial of service", weight: 85 },
      { pattern: /authentication.?bypass/i, suggestion: "authentication bypass", weight: 85 },
      { pattern: /path.?traversal/i, suggestion: "path traversal", weight: 85 },
      { pattern: /memory.?corruption/i, suggestion: "memory corruption", weight: 85 },
      { pattern: /information.?disclosure/i, suggestion: "information disclosure", weight: 85 },
    ];

    smartPatterns.forEach(({ pattern, suggestion, weight }) => {
      if (pattern.test(input) && !suggestions.some((s) => s.text === suggestion)) {
        suggestions.push({
          text: suggestion,
          type: "smart",
          weight,
        });
      }
    });

    // Year-based suggestions
    if (/202[0-9]/.test(input)) {
      const year = input.match(/202[0-9]/)?.[0];
      if (year) {
        suggestions.push({
          text: `CVE-${year}`,
          type: "smart",
          weight: 75,
        });
      }
    }

    // Severity suggestions
    const severities = ["critical", "high", "medium", "low"];
    severities.forEach((severity) => {
      if (severity.startsWith(input.toLowerCase())) {
        suggestions.push({
          text: severity,
          type: "smart",
          weight: 70,
        });
      }
    });
  }

  /**
   * Export saved searches
   */
  exportSavedSearches(): string {
    const searches = this.getSavedSearches();
    return JSON.stringify(searches, null, 2);
  }

  /**
   * Import saved searches
   */
  importSavedSearches(jsonData: string): boolean {
    try {
      const searches = JSON.parse(jsonData);
      if (Array.isArray(searches)) {
        // Validate structure
        const valid = searches.every(
          (s) => s.id && s.name && typeof s.query === "string" && s.filters
        );

        if (valid) {
          this.storeSavedSearches(searches.slice(0, this.maxSavedSearches));
          return true;
        }
      }
    } catch (error) {
      console.warn("Failed to import saved searches:", error);
    }
    return false;
  }

  private storeSavedSearches(searches: SavedSearch[]): void {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(searches));
    } catch (error) {
      console.warn("Failed to save searches:", error);
    }
  }

  private storeRecentSearches(searches: string[]): void {
    try {
      localStorage.setItem(this.recentSearchesKey, JSON.stringify(searches));
    } catch (error) {
      console.warn("Failed to save recent searches:", error);
    }
  }

  private cleanupOldSearches(): void {
    const searches = this.getSavedSearches();
    const cutoff = Date.now() - 90 * 24 * 60 * 60 * 1000; // 90 days
    const cleaned = searches.filter((s) => s.timestamp > cutoff);

    if (cleaned.length !== searches.length) {
      this.storeSavedSearches(cleaned);
    }
  }

  private generateId(): string {
    return `search_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

/**
 * Alpine.js component for saved searches UI
 */
export function createSavedSearchComponent() {
  return {
    savedSearches: new SavedSearches(),
    showSavedSearches: false,
    showSuggestions: false,
    suggestions: [] as SearchSuggestion[],
    savedSearchList: [] as SavedSearch[],
    newSearchName: "",
    showSaveDialog: false,

    init() {
      this.loadSavedSearches();
      this.setupSuggestionHandlers();
    },

    loadSavedSearches() {
      this.savedSearchList = this.savedSearches.getSavedSearches();
    },

    showSaveSearchDialog() {
      this.showSaveDialog = true;
      this.newSearchName = "";
      this.$nextTick(() => {
        const input = document.getElementById("search-name-input") as HTMLInputElement;
        input?.focus();
      });
    },

    saveCurrentSearch() {
      if (!this.newSearchName.trim()) return;

      // Get current state from parent dashboard
      const dashboard = this.getDashboard();
      if (dashboard) {
        const saved = this.savedSearches.saveSearch(
          this.newSearchName,
          dashboard.searchQuery,
          dashboard.filters
        );

        this.loadSavedSearches();
        this.showSaveDialog = false;

        // Show success message
        this.showToast(`Search "${saved.name}" saved successfully`);
      }
    },

    loadSavedSearch(search: SavedSearch) {
      const dashboard = this.getDashboard();
      if (dashboard) {
        // Apply saved search
        dashboard.searchQuery = search.query;
        dashboard.filters = { ...search.filters };
        dashboard.applyFilters();

        // Update count
        this.savedSearches.updateSearchCount(search.id, dashboard.filteredVulns.length);
        this.loadSavedSearches();

        this.showSavedSearches = false;
      }
    },

    deleteSavedSearch(id: string) {
      this.savedSearches.deleteSavedSearch(id);
      this.loadSavedSearches();
    },

    setupSuggestionHandlers() {
      // Handle input events for suggestions
      const searchInput = document.getElementById("search-input");
      if (searchInput) {
        searchInput.addEventListener("input", (e) => {
          this.updateSuggestions((e.target as HTMLInputElement).value);
        });

        searchInput.addEventListener("focus", () => {
          this.showSuggestions = true;
        });

        searchInput.addEventListener("blur", () => {
          // Delay hiding to allow clicks on suggestions
          setTimeout(() => {
            this.showSuggestions = false;
          }, 200);
        });
      }
    },

    updateSuggestions(input: string) {
      const dashboard = this.getDashboard();
      if (dashboard) {
        this.suggestions = this.savedSearches.generateSuggestions(input, dashboard.vulnerabilities);
        this.showSuggestions = input.length > 0 && this.suggestions.length > 0;
      }
    },

    applySuggestion(suggestion: SearchSuggestion) {
      const dashboard = this.getDashboard();
      if (dashboard) {
        dashboard.searchQuery = suggestion.text;
        this.savedSearches.addRecentSearch(suggestion.text);
        dashboard.applyFilters();
        this.showSuggestions = false;
      }
    },

    getSuggestionIcon(type: string): string {
      switch (type) {
        case "recent":
          return "🕒";
        case "vendor":
          return "🏢";
        case "cve":
          return "🔍";
        case "tag":
          return "🏷️";
        case "smart":
          return "💡";
        default:
          return "🔍";
      }
    },

    getDashboard() {
      // Get reference to main dashboard component
      return (window as any).vulnDashboard;
    },

    showToast(message: string) {
      // Simple toast notification
      const toast = document.createElement("div");
      toast.className = "toast";
      toast.textContent = message;
      toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #4ade80;
        color: white;
        padding: 12px 24px;
        border-radius: 8px;
        z-index: 1000;
        animation: slideIn 0.3s ease;
      `;

      document.body.appendChild(toast);

      setTimeout(() => {
        toast.remove();
      }, 3000);
    },

    $nextTick(callback: () => void) {
      // This method is provided by Alpine.js at runtime
      // @ts-ignore
      this.$nextTick(callback);
    },
  };
}
