/**
 * Widget Management System for Dashboard Customization
 */

export interface Widget {
  id: string;
  type: "stats" | "chart" | "table" | "filters" | "alerts" | "timeline" | "custom";
  title: string;
  gridArea?: string;
  size: "small" | "medium" | "large" | "full";
  visible: boolean;
  order: number;
  config: Record<string, any>;
  component?: string;
}

export interface DashboardLayout {
  id: string;
  name: string;
  widgets: Widget[];
  gridTemplate: string;
  breakpoints: Record<string, { template: string; columns: number }>;
  lastModified: number;
}

export interface WidgetPreferences {
  currentLayoutId: string;
  layouts: DashboardLayout[];
  customWidgets: Widget[];
}

export class WidgetManager {
  private preferences: WidgetPreferences;
  private readonly storageKey = "vuln_widget_preferences";
  private readonly defaultLayouts: DashboardLayout[];

  constructor() {
    this.defaultLayouts = this.createDefaultLayouts();
    this.preferences = this.loadPreferences();
  }

  /**
   * Create default dashboard layouts
   */
  private createDefaultLayouts(): DashboardLayout[] {
    return [
      {
        id: "security-analyst",
        name: "Security Analyst",
        widgets: [
          {
            id: "filters",
            type: "filters",
            title: "Search & Filters",
            size: "full",
            visible: true,
            order: 1,
            config: { collapsed: false },
          },
          {
            id: "vulnerability-table",
            type: "table",
            title: "Vulnerabilities",
            size: "large",
            visible: true,
            order: 2,
            config: { pageSize: 50 },
          },
          {
            id: "risk-stats",
            type: "stats",
            title: "Risk Overview",
            size: "small",
            visible: true,
            order: 3,
            config: { showTrends: true },
          },
        ],
        gridTemplate: "repeat(12, 1fr)",
        breakpoints: {
          desktop: { template: "repeat(12, 1fr)", columns: 12 },
          tablet: { template: "repeat(8, 1fr)", columns: 8 },
          mobile: { template: "1fr", columns: 1 },
        },
        lastModified: Date.now(),
      },
      {
        id: "executive-dashboard",
        name: "Executive Dashboard",
        widgets: [
          {
            id: "risk-overview",
            type: "chart",
            title: "Risk Distribution",
            size: "medium",
            visible: true,
            order: 1,
            config: { chartType: "donut" },
          },
          {
            id: "trend-chart",
            type: "chart",
            title: "CVE Trends",
            size: "medium",
            visible: true,
            order: 2,
            config: { chartType: "line", period: "30d" },
          },
          {
            id: "key-metrics",
            type: "stats",
            title: "Key Metrics",
            size: "full",
            visible: true,
            order: 3,
            config: { showComparison: true },
          },
          {
            id: "top-vendors",
            type: "chart",
            title: "Most Affected Vendors",
            size: "medium",
            visible: true,
            order: 4,
            config: { chartType: "bar", limit: 10 },
          },
          {
            id: "recent-activity",
            type: "timeline",
            title: "Recent Activity",
            size: "medium",
            visible: true,
            order: 5,
            config: { limit: 10 },
          },
        ],
        gridTemplate: "repeat(12, 1fr)",
        breakpoints: {
          desktop: { template: "repeat(12, 1fr)", columns: 12 },
          tablet: { template: "repeat(8, 1fr)", columns: 8 },
          mobile: { template: "1fr", columns: 1 },
        },
        lastModified: Date.now(),
      },
      {
        id: "researcher-view",
        name: "Researcher View",
        widgets: [
          {
            id: "advanced-filters",
            type: "filters",
            title: "Advanced Search",
            size: "medium",
            visible: true,
            order: 1,
            config: { showAdvanced: true },
          },
          {
            id: "saved-searches",
            type: "filters",
            title: "Saved Searches",
            size: "small",
            visible: true,
            order: 2,
            config: { component: "saved-searches" },
          },
          {
            id: "detailed-table",
            type: "table",
            title: "Detailed Results",
            size: "full",
            visible: true,
            order: 3,
            config: { showAllColumns: true, pageSize: 100 },
          },
          {
            id: "export-tools",
            type: "custom",
            title: "Export Tools",
            size: "small",
            visible: true,
            order: 4,
            config: { formats: ["json", "csv", "pdf"] },
          },
        ],
        gridTemplate: "repeat(12, 1fr)",
        breakpoints: {
          desktop: { template: "repeat(12, 1fr)", columns: 12 },
          tablet: { template: "repeat(8, 1fr)", columns: 8 },
          mobile: { template: "1fr", columns: 1 },
        },
        lastModified: Date.now(),
      },
    ];
  }

  /**
   * Load preferences from localStorage
   */
  private loadPreferences(): WidgetPreferences {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        const parsed = JSON.parse(stored);
        // Merge with defaults to handle version updates
        return {
          currentLayoutId: parsed.currentLayoutId ?? "security-analyst",
          layouts: [...this.defaultLayouts, ...(parsed.layouts ?? [])],
          customWidgets: parsed.customWidgets ?? [],
        };
      }
    } catch (error) {
      console.warn("Failed to load widget preferences:", error);
    }

    return {
      currentLayoutId: "security-analyst",
      layouts: this.defaultLayouts,
      customWidgets: [],
    };
  }

  /**
   * Save preferences to localStorage
   */
  private savePreferences(): void {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(this.preferences));
    } catch (error) {
      console.error("Failed to save widget preferences:", error);
    }
  }

  /**
   * Get current layout
   */
  getCurrentLayout(): DashboardLayout | null {
    return (
      this.preferences.layouts.find((layout) => layout.id === this.preferences.currentLayoutId) ??
      this.preferences.layouts[0] ??
      null
    );
  }

  /**
   * Get all available layouts
   */
  getLayouts(): DashboardLayout[] {
    return this.preferences.layouts;
  }

  /**
   * Switch to a different layout
   */
  switchLayout(layoutId: string): boolean {
    const layout = this.preferences.layouts.find((l) => l.id === layoutId);
    if (layout) {
      this.preferences.currentLayoutId = layoutId;
      this.savePreferences();
      return true;
    }
    return false;
  }

  /**
   * Create a new custom layout
   */
  createLayout(name: string, baseLayoutId?: string): string {
    const baseLayout = baseLayoutId
      ? this.preferences.layouts.find((l) => l.id === baseLayoutId)
      : this.getCurrentLayout();

    const newLayout: DashboardLayout = {
      id: `custom-${Date.now()}`,
      name,
      widgets: baseLayout ? [...baseLayout.widgets] : [],
      gridTemplate: baseLayout?.gridTemplate ?? "repeat(12, 1fr)",
      breakpoints: baseLayout?.breakpoints ?? {
        desktop: { template: "repeat(12, 1fr)", columns: 12 },
        tablet: { template: "repeat(8, 1fr)", columns: 8 },
        mobile: { template: "1fr", columns: 1 },
      },
      lastModified: Date.now(),
    };

    this.preferences.layouts.push(newLayout);
    this.savePreferences();
    return newLayout.id;
  }

  /**
   * Update widget configuration
   */
  updateWidget(layoutId: string, widgetId: string, updates: Partial<Widget>): boolean {
    const layout = this.preferences.layouts.find((l) => l.id === layoutId);
    if (!layout) return false;

    const widget = layout.widgets.find((w) => w.id === widgetId);
    if (!widget) return false;

    Object.assign(widget, updates);
    layout.lastModified = Date.now();
    this.savePreferences();
    return true;
  }

  /**
   * Add widget to layout
   */
  addWidget(layoutId: string, widget: Omit<Widget, "id" | "order">): boolean {
    const layout = this.preferences.layouts.find((l) => l.id === layoutId);
    if (!layout) return false;

    const newWidget: Widget = {
      ...widget,
      id: `widget-${Date.now()}`,
      order: Math.max(...layout.widgets.map((w) => w.order), 0) + 1,
    };

    layout.widgets.push(newWidget);
    layout.lastModified = Date.now();
    this.savePreferences();
    return true;
  }

  /**
   * Remove widget from layout
   */
  removeWidget(layoutId: string, widgetId: string): boolean {
    const layout = this.preferences.layouts.find((l) => l.id === layoutId);
    if (!layout) return false;

    const index = layout.widgets.findIndex((w) => w.id === widgetId);
    if (index === -1) return false;

    layout.widgets.splice(index, 1);
    layout.lastModified = Date.now();
    this.savePreferences();
    return true;
  }

  /**
   * Reorder widgets in layout
   */
  reorderWidgets(layoutId: string, widgetOrder: string[]): boolean {
    const layout = this.preferences.layouts.find((l) => l.id === layoutId);
    if (!layout) return false;

    // Update order based on new positions
    widgetOrder.forEach((widgetId, index) => {
      const widget = layout.widgets.find((w) => w.id === widgetId);
      if (widget) {
        widget.order = index + 1;
      }
    });

    layout.widgets.sort((a, b) => a.order - b.order);
    layout.lastModified = Date.now();
    this.savePreferences();
    return true;
  }

  /**
   * Delete custom layout
   */
  deleteLayout(layoutId: string): boolean {
    const index = this.preferences.layouts.findIndex((l) => l.id === layoutId);
    if (index === -1) return false;

    // Don't delete default layouts
    const layout = this.preferences.layouts[index];
    if (layout && this.defaultLayouts.some((dl) => dl.id === layout.id)) {
      return false;
    }

    this.preferences.layouts.splice(index, 1);

    // Switch to first available layout if current was deleted
    if (this.preferences.currentLayoutId === layoutId) {
      this.preferences.currentLayoutId = this.preferences.layouts[0]?.id ?? "security-analyst";
    }

    this.savePreferences();
    return true;
  }

  /**
   * Export layout configuration
   */
  exportLayout(layoutId: string): string | null {
    const layout = this.preferences.layouts.find((l) => l.id === layoutId);
    if (!layout) return null;

    return JSON.stringify(layout, null, 2);
  }

  /**
   * Import layout configuration
   */
  importLayout(configJson: string): string | null {
    try {
      const layout: DashboardLayout = JSON.parse(configJson);

      // Validate required fields
      if (!layout.id || !layout.name || !Array.isArray(layout.widgets)) {
        throw new Error("Invalid layout configuration");
      }

      // Generate new ID if conflicting
      if (this.preferences.layouts.some((l) => l.id === layout.id)) {
        layout.id = `imported-${Date.now()}`;
        layout.name = `${layout.name} (Imported)`;
      }

      layout.lastModified = Date.now();
      this.preferences.layouts.push(layout);
      this.savePreferences();

      return layout.id;
    } catch (error) {
      console.error("Failed to import layout:", error);
      return null;
    }
  }

  /**
   * Reset to default layouts
   */
  resetToDefaults(): void {
    this.preferences = {
      currentLayoutId: "security-analyst",
      layouts: this.defaultLayouts,
      customWidgets: [],
    };
    this.savePreferences();
  }

  /**
   * Get widget grid CSS classes based on size and breakpoint
   */
  getWidgetGridClasses(
    widget: Widget,
    breakpoint: "desktop" | "tablet" | "mobile" = "desktop"
  ): string {
    const sizeMap = {
      desktop: {
        small: "widget-small col-span-3",
        medium: "widget-medium col-span-6",
        large: "widget-large col-span-9",
        full: "widget-full col-span-12",
      },
      tablet: {
        small: "widget-small col-span-4",
        medium: "widget-medium col-span-8",
        large: "widget-large col-span-8",
        full: "widget-full col-span-8",
      },
      mobile: {
        small: "widget-small col-span-1",
        medium: "widget-medium col-span-1",
        large: "widget-large col-span-1",
        full: "widget-full col-span-1",
      },
    };

    return sizeMap[breakpoint][widget.size] || "col-span-6";
  }
}

/**
 * Create widget manager instance for Alpine.js
 */
export function createWidgetManager() {
  const manager = new WidgetManager();

  return {
    manager,
    currentLayout: manager.getCurrentLayout(),
    isEditMode: false,
    availableLayouts: manager.getLayouts(),

    // Layout management
    switchLayout(layoutId: string) {
      if (manager.switchLayout(layoutId)) {
        this.currentLayout = manager.getCurrentLayout();
      }
    },

    createLayout(name: string, baseLayoutId?: string) {
      const newId = manager.createLayout(name, baseLayoutId);
      this.availableLayouts = manager.getLayouts();
      this.switchLayout(newId);
    },

    deleteLayout(layoutId: string) {
      if (manager.deleteLayout(layoutId)) {
        this.availableLayouts = manager.getLayouts();
        this.currentLayout = manager.getCurrentLayout();
      }
    },

    // Widget management
    toggleWidget(widgetId: string) {
      if (!this.currentLayout) return;

      const widget = this.currentLayout.widgets.find((w) => w.id === widgetId);
      if (widget) {
        manager.updateWidget(this.currentLayout.id, widgetId, { visible: !widget.visible });
        this.refreshLayout();
      }
    },

    updateWidgetConfig(widgetId: string, config: Record<string, any>) {
      if (!this.currentLayout) return;

      manager.updateWidget(this.currentLayout.id, widgetId, { config });
      this.refreshLayout();
    },

    // Edit mode
    toggleEditMode() {
      this.isEditMode = !this.isEditMode;
    },

    // Utility methods
    refreshLayout() {
      this.currentLayout = manager.getCurrentLayout();
    },

    getVisibleWidgets() {
      return (
        this.currentLayout?.widgets.filter((w) => w.visible).sort((a, b) => a.order - b.order) ?? []
      );
    },

    exportCurrentLayout() {
      if (!this.currentLayout) return null;
      return manager.exportLayout(this.currentLayout.id);
    },

    importLayout(configJson: string) {
      const newId = manager.importLayout(configJson);
      if (newId) {
        this.availableLayouts = manager.getLayouts();
        this.switchLayout(newId);
        return true;
      }
      return false;
    },

    resetToDefaults() {
      manager.resetToDefaults();
      this.availableLayouts = manager.getLayouts();
      this.currentLayout = manager.getCurrentLayout();
    },
  };
}
