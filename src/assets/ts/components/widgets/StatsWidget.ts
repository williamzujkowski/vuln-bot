/**
 * Statistics Widget for Dashboard
 * Displays key vulnerability metrics and trends
 */

export interface StatisticItem {
  label: string;
  value: string | number;
  change?: {
    value: number;
    direction: "positive" | "negative" | "neutral";
    period: string;
  };
  icon?: string;
  color?: "primary" | "success" | "warning" | "error";
}

export class StatsWidget {
  private vulnerabilities: any[] = [];
  private previousData: any[] = [];

  constructor(private config: { showTrends?: boolean; period?: string } = {}) {}

  /**
   * Update widget with new vulnerability data
   */
  updateData(vulnerabilities: any[], previousData?: any[]): void {
    this.vulnerabilities = vulnerabilities ?? [];
    this.previousData = previousData ?? [];
  }

  /**
   * Calculate key statistics
   */
  getStatistics(): StatisticItem[] {
    const stats: StatisticItem[] = [];

    // Total vulnerabilities
    const totalChange = this.config.showTrends ? this.calculateChange("total") : undefined;
    stats.push({
      label: "Total CVEs",
      value: this.vulnerabilities.length,
      ...(totalChange && { change: totalChange }),
      icon: "shield-alert",
      color: "primary",
    });

    // Critical vulnerabilities
    const critical = this.vulnerabilities.filter((v) => v.severity === "CRITICAL").length;
    const criticalChange = this.config.showTrends ? this.calculateChange("critical") : undefined;
    stats.push({
      label: "Critical",
      value: critical,
      ...(criticalChange && { change: criticalChange }),
      icon: "alert-triangle",
      color: "error",
    });

    // High severity vulnerabilities
    const high = this.vulnerabilities.filter((v) => v.severity === "HIGH").length;
    const highChange = this.config.showTrends ? this.calculateChange("high") : undefined;
    stats.push({
      label: "High Severity",
      value: high,
      ...(highChange && { change: highChange }),
      icon: "alert-circle",
      color: "warning",
    });

    // High EPSS scores (>= 90%)
    const highEpss = this.vulnerabilities.filter((v) => v.epssPercentile >= 90).length;
    const highEpssChange = this.config.showTrends ? this.calculateChange("highEpss") : undefined;
    stats.push({
      label: "High EPSS (90%+)",
      value: highEpss,
      ...(highEpssChange && { change: highEpssChange }),
      icon: "trending-up",
      color: "error",
    });

    // KEV (Known Exploited Vulnerabilities)
    const kev = this.vulnerabilities.filter(
      (v) =>
        v.metadata?.tags?.includes("CISA-KEV") ||
        v.enrichments?.cisa_kev?.isKnownExploited === true
    ).length;
    const kevChange = this.config.showTrends ? this.calculateChange("kev") : undefined;
    stats.push({
      label: "KEV Listed",
      value: kev,
      ...(kevChange && { change: kevChange }),
      icon: "zap",
      color: "error",
    });

    // Average CVSS score
    const avgCvss =
      this.vulnerabilities.length > 0
        ? (
            this.vulnerabilities.reduce((sum, v) => sum + (v.cvssScore ?? 0), 0) /
            this.vulnerabilities.length
          ).toFixed(1)
        : "0.0";
    const avgCvssChange = this.config.showTrends ? this.calculateChange("avgCvss") : undefined;
    stats.push({
      label: "Avg CVSS",
      value: avgCvss,
      ...(avgCvssChange && { change: avgCvssChange }),
      icon: "bar-chart",
      color: "primary",
    });

    // Recent vulnerabilities (last 7 days)
    const recentDate = new Date();
    recentDate.setDate(recentDate.getDate() - 7);
    const recent = this.vulnerabilities.filter((v) => {
      const pubDate = new Date(v.publishedDate);
      return pubDate >= recentDate;
    }).length;
    const recentChange = this.config.showTrends ? this.calculateChange("recent") : undefined;
    stats.push({
      label: "Last 7 Days",
      value: recent,
      ...(recentChange && { change: recentChange }),
      icon: "clock",
      color: "primary",
    });

    // Top affected vendor
    const vendorCounts = this.getVendorCounts();
    const topVendor = vendorCounts[0];
    if (topVendor) {
      stats.push({
        label: `Top Vendor`,
        value: `${topVendor.vendor} (${topVendor.count})`,
        icon: "building",
        color: "primary",
      });
    }

    return stats;
  }

  /**
   * Calculate percentage change from previous period
   */
  private calculateChange(metric: string): StatisticItem["change"] {
    if (!this.previousData || this.previousData.length === 0) {
      return undefined;
    }

    let currentValue: number;
    let previousValue: number;

    switch (metric) {
      case "total":
        currentValue = this.vulnerabilities.length;
        previousValue = this.previousData.length;
        break;
      case "critical":
        currentValue = this.vulnerabilities.filter((v) => v.severity === "CRITICAL").length;
        previousValue = this.previousData.filter((v) => v.severity === "CRITICAL").length;
        break;
      case "high":
        currentValue = this.vulnerabilities.filter((v) => v.severity === "HIGH").length;
        previousValue = this.previousData.filter((v) => v.severity === "HIGH").length;
        break;
      case "highEpss":
        currentValue = this.vulnerabilities.filter((v) => v.epssPercentile >= 90).length;
        previousValue = this.previousData.filter((v) => v.epssPercentile >= 90).length;
        break;
      case "kev":
        currentValue = this.vulnerabilities.filter(
          (v) =>
            v.metadata?.tags?.includes("CISA-KEV") ||
            v.enrichments?.cisa_kev?.isKnownExploited === true
        ).length;
        previousValue = this.previousData.filter(
          (v) =>
            v.metadata?.tags?.includes("CISA-KEV") ||
            v.enrichments?.cisa_kev?.isKnownExploited === true
        ).length;
        break;
      case "avgCvss":
        currentValue =
          this.vulnerabilities.length > 0
            ? this.vulnerabilities.reduce((sum, v) => sum + (v.cvssScore ?? 0), 0) /
              this.vulnerabilities.length
            : 0;
        previousValue =
          this.previousData.length > 0
            ? this.previousData.reduce((sum, v) => sum + (v.cvssScore ?? 0), 0) /
              this.previousData.length
            : 0;
        break;
      case "recent":
        const recentDate = new Date();
        recentDate.setDate(recentDate.getDate() - 7);
        currentValue = this.vulnerabilities.filter((v) => {
          const pubDate = new Date(v.publishedDate);
          return pubDate >= recentDate;
        }).length;
        previousValue = this.previousData.filter((v) => {
          const pubDate = new Date(v.publishedDate);
          const compareDate = new Date(recentDate);
          compareDate.setDate(compareDate.getDate() - 7);
          return pubDate >= compareDate && pubDate < recentDate;
        }).length;
        break;
      default:
        return undefined;
    }

    if (previousValue === 0) {
      return currentValue > 0
        ? {
            value: 100,
            direction: "positive",
            period: this.config.period ?? "7d",
          }
        : undefined;
    }

    const changePercent = ((currentValue - previousValue) / previousValue) * 100;
    const direction = changePercent > 0 ? "positive" : changePercent < 0 ? "negative" : "neutral";

    return {
      value: Math.abs(Math.round(changePercent)),
      direction,
      period: this.config.period ?? "7d",
    };
  }

  /**
   * Get vendor vulnerability counts
   */
  private getVendorCounts(): Array<{ vendor: string; count: number }> {
    const vendorMap = new Map<string, number>();

    this.vulnerabilities.forEach((vuln) => {
      const vendors = vuln.vendors;
      if (vendors && Array.isArray(vendors)) {
        vendors.forEach((vendor: string) => {
          if (vendor && typeof vendor === "string") {
            vendorMap.set(vendor, (vendorMap.get(vendor) ?? 0) + 1);
          }
        });
      }
    });

    return Array.from(vendorMap.entries())
      .map(([vendor, count]) => ({ vendor, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  /**
   * Get severity distribution
   */
  getSeverityDistribution(): Array<{ severity: string; count: number; percentage: number }> {
    const severityMap = new Map<string, number>();
    const total = this.vulnerabilities.length;

    this.vulnerabilities.forEach((vuln) => {
      const severity = vuln.severity ?? "UNKNOWN";
      severityMap.set(severity, (severityMap.get(severity) ?? 0) + 1);
    });

    return Array.from(severityMap.entries())
      .map(([severity, count]) => ({
        severity,
        count,
        percentage: total > 0 ? Math.round((count / total) * 100) : 0,
      }))
      .sort((a, b) => {
        const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
        return (
          (order[b.severity as keyof typeof order] ?? 0) -
          (order[a.severity as keyof typeof order] ?? 0)
        );
      });
  }

  /**
   * Get EPSS distribution ranges
   */
  getEpssDistribution(): Array<{ range: string; count: number; percentage: number }> {
    const ranges = [
      { range: "90-100%", min: 90, max: 100 },
      { range: "70-89%", min: 70, max: 89 },
      { range: "50-69%", min: 50, max: 69 },
      { range: "25-49%", min: 25, max: 49 },
      { range: "0-24%", min: 0, max: 24 },
    ];

    const total = this.vulnerabilities.length;

    return ranges.map(({ range, min, max }) => {
      const count = this.vulnerabilities.filter((vuln) => {
        const epss = vuln.epssPercentile ?? 0;
        return epss >= min && epss <= max;
      }).length;

      return {
        range,
        count,
        percentage: total > 0 ? Math.round((count / total) * 100) : 0,
      };
    });
  }

  /**
   * Get timeline data for trend analysis
   */
  getTimelineData(
    days: number = 30
  ): Array<{ date: string; count: number; critical: number; high: number }> {
    const timeline: Array<{ date: string; count: number; critical: number; high: number }> = [];
    const endDate = new Date();

    for (let i = days - 1; i >= 0; i--) {
      const date = new Date(endDate);
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split("T")[0] ?? "";

      const dayVulns = this.vulnerabilities.filter((vuln) => {
        const pubDate = new Date(vuln.publishedDate).toISOString().split("T")[0];
        return pubDate === dateStr;
      });

      timeline.push({
        date: dateStr,
        count: dayVulns.length,
        critical: dayVulns.filter((v) => v.severity === "CRITICAL").length,
        high: dayVulns.filter((v) => v.severity === "HIGH").length,
      });
    }

    return timeline;
  }
}

/**
 * Create stats widget for Alpine.js
 */
export function createStatsWidget(config: { showTrends?: boolean; period?: string } = {}) {
  const widget = new StatsWidget(config);

  return {
    widget,
    statistics: [] as StatisticItem[],
    severityDistribution: [] as any[],
    epssDistribution: [] as any[],
    timelineData: [] as any[],
    loading: false,
    error: null as string | null,

    // Initialize with data
    init(vulnerabilities: any[], previousData?: any[]) {
      this.updateData(vulnerabilities, previousData);
    },

    // Update widget data
    updateData(vulnerabilities: any[], previousData?: any[]) {
      this.loading = true;
      this.error = null;

      try {
        widget.updateData(vulnerabilities, previousData);
        this.statistics = widget.getStatistics();
        this.severityDistribution = widget.getSeverityDistribution();
        this.epssDistribution = widget.getEpssDistribution();
        this.timelineData = widget.getTimelineData();
      } catch (error) {
        this.error = "Failed to calculate statistics";
        console.error("Stats widget error:", error);
      } finally {
        this.loading = false;
      }
    },

    // Get formatted change text
    getChangeText(change: StatisticItem["change"]): string {
      if (!change) return "";

      const sign =
        change.direction === "positive" ? "+" : change.direction === "negative" ? "-" : "";
      return `${sign}${change.value}% vs ${change.period}`;
    },

    // Get change CSS class
    getChangeClass(change: StatisticItem["change"]): string {
      if (!change) return "";
      return `stat-change ${change.direction}`;
    },

    // Format large numbers
    formatValue(value: string | number): string {
      if (typeof value === "number") {
        if (value >= 1000000) {
          return (value / 1000000).toFixed(1) + "M";
        } else if (value >= 1000) {
          return (value / 1000).toFixed(1) + "K";
        }
        return value.toString();
      }
      return value;
    },

    // Get icon SVG
    getIcon(iconName: string): string {
      const icons: Record<string, string> = {
        "shield-alert":
          '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
        "alert-triangle":
          '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="m12 17 .01 0"/>',
        "alert-circle": '<circle cx="12" cy="12" r="10"/><path d="m9 9 6 6"/><path d="m15 9-6 6"/>',
        "trending-up":
          '<polyline points="22,7 13.5,15.5 8.5,10.5 2,17"/><polyline points="16,7 22,7 22,13"/>',
        zap: '<polygon points="13,2 3,14 12,14 11,22 21,10 12,10 13,2"/>',
        "bar-chart":
          '<line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/>',
        clock: '<circle cx="12" cy="12" r="10"/><polyline points="12,6 12,12 16,14"/>',
        building:
          '<path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z"/><path d="M6 12h4"/><path d="M6 8h4"/><path d="M16 8h2"/><path d="M16 12h2"/><path d="M16 16h2"/>',
      };

      return icons[iconName] ?? "";
    },
  };
}
