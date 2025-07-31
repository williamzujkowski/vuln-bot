/**
 * Virtual Scrolling Component for Performance Optimization
 * Renders only visible rows to handle large datasets efficiently
 */

export interface VirtualScrollItem {
  id: string;
  data: any;
  height?: number;
}

export interface VirtualScrollConfig {
  itemHeight: number;
  containerHeight: number;
  overscan: number; // Number of items to render outside viewport
  renderItem: (item: VirtualScrollItem, index: number) => HTMLElement;
  getItemHeight?: (item: VirtualScrollItem, index: number) => number;
}

export class VirtualScrollManager {
  private container: HTMLElement;
  private viewport!: HTMLElement;
  private config: VirtualScrollConfig;
  private items: VirtualScrollItem[] = [];
  private startIndex = 0;
  private endIndex = 0;
  private scrollTop = 0;
  private totalHeight = 0;
  private renderedItems: Map<string, HTMLElement> = new Map();
  private resizeObserver: ResizeObserver | null = null;
  private scrollTimeout: number | null = null;

  constructor(container: HTMLElement, config: VirtualScrollConfig) {
    this.container = container;
    this.config = config;
    this.init();
  }

  private init(): void {
    this.setupContainer();
    this.setupViewport();
    this.setupScrollListener();
    this.setupResizeObserver();
  }

  private setupContainer(): void {
    this.container.style.position = "relative";
    this.container.style.overflow = "auto";
    this.container.style.height = `${this.config.containerHeight}px`;
  }

  private setupViewport(): void {
    this.viewport = document.createElement("div");
    this.viewport.className = "virtual-scroll-viewport";
    this.viewport.style.cssText = `
      position: relative;
      width: 100%;
      min-height: 100%;
    `;
    this.container.appendChild(this.viewport);
  }

  private setupScrollListener(): void {
    let ticking = false;

    this.container.addEventListener("scroll", () => {
      if (!ticking) {
        requestAnimationFrame(() => {
          this.handleScroll();
          ticking = false;
        });
        ticking = true;
      }

      // Track scrolling state for optimizations
      if (this.scrollTimeout) {
        clearTimeout(this.scrollTimeout);
      }
      this.scrollTimeout = window.setTimeout(() => {
        // Scrolling ended
      }, 150);
    });
  }

  private setupResizeObserver(): void {
    if ("ResizeObserver" in window) {
      this.resizeObserver = new ResizeObserver(() => {
        this.updateLayout();
      });
      this.resizeObserver.observe(this.container);
    }
  }

  private handleScroll(): void {
    this.scrollTop = this.container.scrollTop;
    this.updateVisibleRange();
    this.renderItems();
  }

  private updateVisibleRange(): void {
    const containerHeight = this.container.clientHeight;
    const itemHeight = this.config.itemHeight;

    // Calculate visible range with overscan
    const startIndex = Math.max(0, Math.floor(this.scrollTop / itemHeight) - this.config.overscan);
    const visibleItemCount = Math.ceil(containerHeight / itemHeight);
    const endIndex = Math.min(
      this.items.length,
      startIndex + visibleItemCount + this.config.overscan * 2
    );

    this.startIndex = startIndex;
    this.endIndex = endIndex;
  }

  private renderItems(): void {
    // Clear existing rendered items that are outside the visible range
    this.renderedItems.forEach((element, id) => {
      const itemIndex = this.items.findIndex((item) => item.id === id);
      if (itemIndex < this.startIndex || itemIndex >= this.endIndex) {
        element.remove();
        this.renderedItems.delete(id);
      }
    });

    // Render items in the visible range
    for (let i = this.startIndex; i < this.endIndex; i++) {
      const item = this.items[i];
      if (!item) continue;

      if (!this.renderedItems.has(item.id)) {
        const element = this.config.renderItem(item, i);
        this.positionItem(element, i);
        this.viewport.appendChild(element);
        this.renderedItems.set(item.id, element);
      }
    }

    // Update total height for scrollbar
    this.updateTotalHeight();
  }

  private positionItem(element: HTMLElement, index: number): void {
    const item = this.items[index];
    if (!item) return;

    const itemHeight = this.config.getItemHeight
      ? this.config.getItemHeight(item, index)
      : this.config.itemHeight;

    element.style.position = "absolute";
    element.style.top = `${index * this.config.itemHeight}px`;
    element.style.height = `${itemHeight}px`;
    element.style.width = "100%";
    element.style.boxSizing = "border-box";
  }

  private updateTotalHeight(): void {
    this.totalHeight = this.items.length * this.config.itemHeight;
    this.viewport.style.height = `${this.totalHeight}px`;
  }

  private updateLayout(): void {
    this.updateVisibleRange();
    this.renderItems();
  }

  /**
   * Set the items to be rendered
   */
  setItems(items: VirtualScrollItem[]): void {
    this.items = items;
    this.updateLayout();
  }

  /**
   * Update a specific item
   */
  updateItem(id: string, data: any): void {
    const index = this.items.findIndex((item) => item.id === id);
    if (index >= 0 && this.items[index]) {
      this.items[index].data = data;

      // Re-render if item is currently visible
      if (index >= this.startIndex && index < this.endIndex) {
        const existingElement = this.renderedItems.get(id);
        if (existingElement) {
          existingElement.remove();
          this.renderedItems.delete(id);
        }

        const item = this.items[index];
        if (item) {
          const newElement = this.config.renderItem(item, index);
          this.positionItem(newElement, index);
          this.viewport.appendChild(newElement);
          this.renderedItems.set(id, newElement);
        }
      }
    }
  }

  /**
   * Add new items
   */
  addItems(newItems: VirtualScrollItem[]): void {
    this.items.push(...newItems);
    this.updateLayout();
  }

  /**
   * Remove items
   */
  removeItems(ids: string[]): void {
    this.items = this.items.filter((item) => !ids.includes(item.id));

    // Remove from rendered items
    ids.forEach((id) => {
      const element = this.renderedItems.get(id);
      if (element) {
        element.remove();
        this.renderedItems.delete(id);
      }
    });

    this.updateLayout();
  }

  /**
   * Scroll to a specific item
   */
  scrollToItem(id: string): void {
    const index = this.items.findIndex((item) => item.id === id);
    if (index >= 0) {
      const targetScrollTop = index * this.config.itemHeight;
      this.container.scrollTo({
        top: targetScrollTop,
        behavior: "smooth",
      });
    }
  }

  /**
   * Get current scroll position info
   */
  getScrollInfo(): {
    scrollTop: number;
    startIndex: number;
    endIndex: number;
    totalItems: number;
    visibleItems: number;
  } {
    return {
      scrollTop: this.scrollTop,
      startIndex: this.startIndex,
      endIndex: this.endIndex,
      totalItems: this.items.length,
      visibleItems: this.endIndex - this.startIndex,
    };
  }

  /**
   * Cleanup
   */
  destroy(): void {
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
    }

    if (this.scrollTimeout) {
      clearTimeout(this.scrollTimeout);
    }

    this.renderedItems.clear();
  }
}

/**
 * Alpine.js component for virtual scrolling vulnerability table
 */
export function createVirtualTableComponent() {
  return {
    virtualScroll: null as VirtualScrollManager | null,
    isVirtualized: false,
    virtualizationThreshold: 100, // Virtualize when more than 100 items

    init() {
      // Note: Manual watching will be set up by the parent component
    },

    handleVulnerabilityChange(vulnerabilities: any[]) {
      const shouldVirtualize = vulnerabilities.length > this.virtualizationThreshold;

      if (shouldVirtualize && !this.isVirtualized) {
        this.enableVirtualization(vulnerabilities);
      } else if (!shouldVirtualize && this.isVirtualized) {
        this.disableVirtualization();
      } else if (this.isVirtualized && this.virtualScroll) {
        this.updateVirtualItems(vulnerabilities);
      }
    },

    enableVirtualization(vulnerabilities: any[]) {
      const tableContainer = document.querySelector(".vuln-table") as HTMLElement;
      if (!tableContainer) return;

      // Hide regular table
      const regularTable = tableContainer.querySelector("table");
      if (regularTable) {
        regularTable.style.display = "none";
      }

      // Create virtual scroll container
      const virtualContainer = document.createElement("div");
      virtualContainer.className = "virtual-vuln-table";
      virtualContainer.style.height = "600px"; // Fixed height for virtual scrolling
      tableContainer.appendChild(virtualContainer);

      const config: VirtualScrollConfig = {
        itemHeight: 60, // Approximate row height
        containerHeight: 600,
        overscan: 5,
        renderItem: (item: VirtualScrollItem, index: number) => {
          return this.renderVulnerabilityRow(item.data, index);
        },
      };

      this.virtualScroll = new VirtualScrollManager(virtualContainer, config);
      this.updateVirtualItems(vulnerabilities);
      this.isVirtualized = true;

      // Show virtualization indicator
      this.showVirtualizationStatus(true, vulnerabilities.length);
    },

    disableVirtualization() {
      if (this.virtualScroll) {
        this.virtualScroll.destroy();
        this.virtualScroll = null;
      }

      // Remove virtual container
      const virtualContainer = document.querySelector(".virtual-vuln-table");
      if (virtualContainer) {
        virtualContainer.remove();
      }

      // Show regular table
      const regularTable = document.querySelector(".vuln-table table") as HTMLElement;
      if (regularTable) {
        regularTable.style.display = "";
      }

      this.isVirtualized = false;
      this.showVirtualizationStatus(false, 0);
    },

    updateVirtualItems(vulnerabilities: any[]) {
      if (!this.virtualScroll) return;

      const items: VirtualScrollItem[] = vulnerabilities.map((vuln) => ({
        id: vuln.cveId,
        data: vuln,
      }));

      this.virtualScroll.setItems(items);
    },

    renderVulnerabilityRow(vulnerability: any, _index: number): HTMLElement {
      const row = document.createElement("div");
      row.className = "virtual-vuln-row";
      row.setAttribute("role", "row");

      // Apply zebra striping
      if (_index % 2 === 1) {
        row.classList.add("virtual-vuln-row--alt");
      }

      row.innerHTML = `
        <div class="virtual-vuln-cell virtual-vuln-cell--cve">
          <button 
            type="button"
            class="cve-link-button"
            onclick="window.vulnDashboard.openCveModal('${vulnerability.cveId}')"
            aria-label="View details for ${vulnerability.cveId}"
          >
            ${vulnerability.cveId}
          </button>
        </div>
        <div class="virtual-vuln-cell virtual-vuln-cell--title">
          ${this.truncateText(vulnerability.title, 80)}
        </div>
        <div class="virtual-vuln-cell virtual-vuln-cell--cvss">
          <span class="score ${this.getSeverityClass(vulnerability.cvssScore)}" 
                aria-label="CVSS score: ${vulnerability.cvssScore}, " +
                  "severity: ${vulnerability.severity}">
            ${vulnerability.cvssScore ?? "N/A"}
          </span>
        </div>
        <div class="virtual-vuln-cell virtual-vuln-cell--epss">
          <span aria-label="EPSS percentile: ${vulnerability.epssPercentile}%">
            ${vulnerability.epssPercentile}%
          </span>
        </div>
        <div class="virtual-vuln-cell virtual-vuln-cell--date">
          <time datetime="${vulnerability.publishedDate}" 
                aria-label="Published on ${this.formatDate(vulnerability.publishedDate)}">
            ${this.formatDate(vulnerability.publishedDate)}
          </time>
        </div>
      `;

      // Add hover and focus interactions
      row.addEventListener("mouseenter", () => {
        row.classList.add("virtual-vuln-row--hover");
      });

      row.addEventListener("mouseleave", () => {
        row.classList.remove("virtual-vuln-row--hover");
      });

      return row;
    },

    showVirtualizationStatus(enabled: boolean, itemCount: number) {
      let statusElement = document.getElementById("virtualization-status");

      if (!statusElement) {
        statusElement = document.createElement("div");
        statusElement.id = "virtualization-status";
        statusElement.className = "virtualization-status";
        statusElement.setAttribute("role", "status");
        statusElement.setAttribute("aria-live", "polite");

        const tableSection = document.querySelector(".vuln-table-section");
        if (tableSection) {
          tableSection.insertBefore(statusElement, tableSection.firstChild);
        }
      }

      if (enabled) {
        statusElement.innerHTML = `
          <div class="virtualization-indicator">
            <span class="virtualization-icon">⚡</span>
            <span class="virtualization-text">
              Virtual scrolling enabled for ${itemCount.toLocaleString()} items
            </span>
            <span class="virtualization-help">
              Only visible rows are rendered for optimal performance
            </span>
          </div>
        `;
        statusElement.style.display = "block";
      } else {
        statusElement.style.display = "none";
      }
    },

    truncateText(text: string, maxLength: number): string {
      if (text.length <= maxLength) return text;
      return text.substring(0, maxLength - 3) + "...";
    },

    getSeverityClass(score: number): string {
      if (score >= 9) return "severity-critical";
      if (score >= 7) return "severity-high";
      if (score >= 4) return "severity-medium";
      if (score > 0) return "severity-low";
      return "severity-none";
    },

    formatDate(dateStr: string): string {
      const date = new Date(dateStr);
      return date.toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    },

    scrollToTop() {
      if (this.virtualScroll) {
        this.virtualScroll.scrollToItem(this.virtualScroll.getScrollInfo().startIndex.toString());
      } else {
        const tableContainer = document.querySelector(".vuln-table");
        if (tableContainer) {
          tableContainer.scrollTo({ top: 0, behavior: "smooth" });
        }
      }
    },

    getPerformanceInfo(): any {
      if (this.virtualScroll) {
        const info = this.virtualScroll.getScrollInfo();
        return {
          virtualized: true,
          totalItems: info.totalItems,
          renderedItems: info.visibleItems,
          scrollPosition: Math.round((info.scrollTop / (info.totalItems * 60)) * 100),
        };
      }

      return {
        virtualized: false,
        totalItems: 0,
        renderedItems: 0,
        scrollPosition: 0,
      };
    },
  };
}
