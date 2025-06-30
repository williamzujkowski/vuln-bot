/**
 * Security Alert System and Quick Actions Component
 * Provides contextual security alerts and quick action buttons for vulnerability management
 */

export interface SecurityAlert {
  id: string;
  type: "critical" | "warning" | "info" | "success";
  title: string;
  message: string;
  actions?: SecurityAction[];
  timestamp: number;
  priority: number;
  dismissible: boolean;
  autoHide?: number; // milliseconds
  metadata?: Record<string, any>;
}

export interface SecurityAction {
  id: string;
  label: string;
  icon?: string;
  type: "primary" | "secondary" | "danger";
  handler: () => void | Promise<void>;
  shortcut?: string;
}

export class SecurityAlertSystem {
  private alerts: SecurityAlert[] = [];
  private alertContainer: HTMLElement | null = null;
  private maxAlerts = 5;
  private subscribers: ((alerts: SecurityAlert[]) => void)[] = [];

  constructor() {
    this.init();
  }

  private init(): void {
    this.createAlertContainer();
    this.setupKeyboardShortcuts();
  }

  private createAlertContainer(): void {
    this.alertContainer = document.createElement("div");
    this.alertContainer.id = "security-alerts-container";
    this.alertContainer.className = "security-alerts-container";
    this.alertContainer.setAttribute("role", "status");
    this.alertContainer.setAttribute("aria-live", "polite");
    this.alertContainer.setAttribute("aria-atomic", "false");

    document.body.appendChild(this.alertContainer);
  }

  /**
   * Add a security alert
   */
  addAlert(alert: Omit<SecurityAlert, "id" | "timestamp">): string {
    const newAlert: SecurityAlert = {
      ...alert,
      id: this.generateId(),
      timestamp: Date.now(),
    };

    // Add to beginning of array (most recent first)
    this.alerts.unshift(newAlert);

    // Limit number of alerts
    if (this.alerts.length > this.maxAlerts) {
      this.alerts = this.alerts.slice(0, this.maxAlerts);
    }

    this.renderAlerts();
    this.notifySubscribers();

    // Auto-hide if specified
    if (alert.autoHide) {
      setTimeout(() => {
        this.removeAlert(newAlert.id);
      }, alert.autoHide);
    }

    return newAlert.id;
  }

  /**
   * Remove an alert by ID
   */
  removeAlert(id: string): void {
    this.alerts = this.alerts.filter((alert) => alert.id !== id);
    this.renderAlerts();
    this.notifySubscribers();
  }

  /**
   * Clear all alerts
   */
  clearAlerts(): void {
    this.alerts = [];
    this.renderAlerts();
    this.notifySubscribers();
  }

  /**
   * Get all current alerts
   */
  getAlerts(): SecurityAlert[] {
    return [...this.alerts];
  }

  /**
   * Subscribe to alert changes
   */
  subscribe(callback: (alerts: SecurityAlert[]) => void): () => void {
    this.subscribers.push(callback);

    // Return unsubscribe function
    return () => {
      this.subscribers = this.subscribers.filter((sub) => sub !== callback);
    };
  }

  private notifySubscribers(): void {
    this.subscribers.forEach((callback) => callback(this.getAlerts()));
  }

  private renderAlerts(): void {
    if (!this.alertContainer) return;

    this.alertContainer.innerHTML = "";

    this.alerts.forEach((alert) => {
      const alertElement = this.createAlertElement(alert);
      this.alertContainer!.appendChild(alertElement);
    });
  }

  private createAlertElement(alert: SecurityAlert): HTMLElement {
    const alertDiv = document.createElement("div");
    alertDiv.className = `security-alert security-alert--${alert.type}`;
    alertDiv.setAttribute("role", "alert");
    alertDiv.setAttribute("aria-labelledby", `alert-title-${alert.id}`);
    alertDiv.setAttribute("aria-describedby", `alert-message-${alert.id}`);

    const iconMap = {
      critical: "🚨",
      warning: "⚠️",
      info: "ℹ️",
      success: "✅",
    };

    alertDiv.innerHTML = `
      <div class="security-alert__header">
        <span class="security-alert__icon" aria-hidden="true">${iconMap[alert.type]}</span>
        <h3 id="alert-title-${alert.id}" class="security-alert__title">${alert.title}</h3>
        ${
          alert.dismissible
            ? `
          <button 
            class="security-alert__dismiss" 
            aria-label="Dismiss alert"
            onclick="securityAlerts.removeAlert('${alert.id}')"
          >
            ×
          </button>
        `
            : ""
        }
      </div>
      <div id="alert-message-${alert.id}" class="security-alert__message">
        ${alert.message}
      </div>
      ${
        alert.actions && alert.actions.length > 0
          ? `
        <div class="security-alert__actions">
          ${alert.actions
            .map(
              (action) => `
            <button 
              class="security-alert__action security-alert__action--${action.type}"
              onclick="securityAlerts.executeAction('${alert.id}', '${action.id}')"
              ${action.shortcut ? `title="Shortcut: ${action.shortcut}"` : ""}
            >
              ${action.icon ? `<span class="action-icon">${action.icon}</span>` : ""}
              ${action.label}
            </button>
          `
            )
            .join("")}
        </div>
      `
          : ""
      }
      <div class="security-alert__timestamp">
        ${new Date(alert.timestamp).toLocaleTimeString()}
      </div>
    `;

    return alertDiv;
  }

  /**
   * Execute an action from an alert
   */
  async executeAction(alertId: string, actionId: string): Promise<void> {
    const alert = this.alerts.find((a) => a.id === alertId);
    if (!alert?.actions) return;

    const action = alert.actions.find((a) => a.id === actionId);
    if (!action) return;

    try {
      await action.handler();
    } catch (error) {
      console.error("Failed to execute alert action:", error);
      this.addAlert({
        type: "critical",
        title: "Action Failed",
        message: `Failed to execute action: ${error instanceof Error ? error.message : "Unknown error"}`,
        priority: 100,
        dismissible: true,
        autoHide: 5000,
      });
    }
  }

  private setupKeyboardShortcuts(): void {
    document.addEventListener("keydown", (event) => {
      // Alt + A to show/focus alerts
      if (event.altKey && event.key === "a") {
        event.preventDefault();
        this.focusFirstAlert();
      }

      // Escape to dismiss focused alert
      if (event.key === "Escape" && document.activeElement?.closest(".security-alert")) {
        const alertElement = document.activeElement.closest(".security-alert") as HTMLElement;
        const alertId = alertElement
          ?.querySelector('[id^="alert-title-"]')
          ?.id.replace("alert-title-", "");
        if (alertId) {
          this.removeAlert(alertId);
        }
      }
    });
  }

  private focusFirstAlert(): void {
    const firstAlert = this.alertContainer?.querySelector(".security-alert") as HTMLElement;
    firstAlert?.focus();
  }

  private generateId(): string {
    return `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

/**
 * Quick Actions Manager for security-specific operations
 */
export class QuickActionsManager {
  private actions: Map<string, SecurityAction> = new Map();
  private container: HTMLElement | null = null;

  constructor() {
    this.init();
    this.registerDefaultActions();
  }

  private init(): void {
    this.createContainer();
  }

  private createContainer(): void {
    this.container = document.createElement("div");
    this.container.id = "quick-actions-container";
    this.container.className = "quick-actions-container";
    this.container.setAttribute("role", "toolbar");
    this.container.setAttribute("aria-label", "Quick security actions");

    // Position in top-right corner
    this.container.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      z-index: 1000;
      display: flex;
      gap: 8px;
      background: rgba(255, 255, 255, 0.95);
      border-radius: 12px;
      padding: 8px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
      backdrop-filter: blur(8px);
    `;

    document.body.appendChild(this.container);
  }

  /**
   * Register a quick action
   */
  registerAction(action: SecurityAction): void {
    this.actions.set(action.id, action);
    this.renderActions();
  }

  /**
   * Remove a quick action
   */
  removeAction(id: string): void {
    this.actions.delete(id);
    this.renderActions();
  }

  private renderActions(): void {
    if (!this.container) return;

    this.container.innerHTML = "";

    this.actions.forEach((action) => {
      const button = document.createElement("button");
      button.className = `quick-action quick-action--${action.type}`;
      button.setAttribute("aria-label", action.label);
      button.setAttribute(
        "title",
        action.shortcut ? `${action.label} (${action.shortcut})` : action.label
      );

      button.innerHTML = `
        ${action.icon ? `<span class="quick-action__icon">${action.icon}</span>` : ""}
        <span class="quick-action__label">${action.label}</span>
      `;

      button.onclick = async () => {
        try {
          await action.handler();
        } catch (error) {
          console.error("Quick action failed:", error);
        }
      };

      this.container!.appendChild(button);
    });
  }

  private registerDefaultActions(): void {
    // Emergency: Show only critical vulnerabilities
    this.registerAction({
      id: "emergency-filter",
      label: "Emergency",
      icon: "🚨",
      type: "danger",
      shortcut: "Alt+E",
      handler: () => {
        const dashboard = (window as any).vulnDashboard;
        if (dashboard) {
          dashboard.filters.severity = "CRITICAL";
          dashboard.filters.epssMin = 90;
          dashboard.applyFilters();

          (window as any).securityAlerts.addAlert({
            type: "warning",
            title: "Emergency Filter Applied",
            message: "Showing only Critical vulnerabilities with EPSS ≥ 90%",
            priority: 90,
            dismissible: true,
            autoHide: 5000,
          });
        }
      },
    });

    // Quick export for SIEM
    this.registerAction({
      id: "siem-export",
      label: "SIEM Export",
      icon: "📡",
      type: "primary",
      shortcut: "Alt+S",
      handler: () => {
        const dashboard = (window as any).vulnDashboard;
        if (dashboard) {
          // Export in SIEM-friendly JSON format
          const siemData = dashboard.filteredVulns.map((vuln: any) => ({
            timestamp: new Date().toISOString(),
            event_type: "vulnerability_alert",
            severity: vuln.severity,
            cve_id: vuln.cveId,
            cvss_score: vuln.cvssScore,
            epss_score: vuln.epssPercentile,
            vendors: vuln.vendors,
            products: vuln.products,
            tags: vuln.tags,
            published_date: vuln.publishedDate,
          }));

          const blob = new Blob([JSON.stringify(siemData, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url;
          a.download = `vuln-siem-export-${new Date().toISOString().slice(0, 10)}.json`;
          a.click();
          URL.revokeObjectURL(url);

          (window as any).securityAlerts.addAlert({
            type: "success",
            title: "SIEM Export Complete",
            message: `Exported ${siemData.length} vulnerabilities in SIEM format`,
            priority: 70,
            dismissible: true,
            autoHide: 3000,
          });
        }
      },
    });

    // Risk assessment summary
    this.registerAction({
      id: "risk-summary",
      label: "Risk Summary",
      icon: "📊",
      type: "secondary",
      shortcut: "Alt+R",
      handler: () => {
        const dashboard = (window as any).vulnDashboard;
        if (dashboard) {
          const vulns = dashboard.filteredVulns;
          const critical = vulns.filter((v: any) => v.severity === "CRITICAL").length;
          const high = vulns.filter((v: any) => v.severity === "HIGH").length;
          const highEpss = vulns.filter((v: any) => v.epssPercentile >= 80).length;

          (window as any).securityAlerts.addAlert({
            type: "info",
            title: "Risk Assessment Summary",
            message: `
              <strong>Current Risk Profile:</strong><br>
              • ${critical} Critical vulnerabilities<br>
              • ${high} High severity vulnerabilities<br>
              • ${highEpss} vulnerabilities with EPSS ≥ 80%<br>
              • Total filtered: ${vulns.length} vulnerabilities
            `,
            priority: 60,
            dismissible: true,
            actions: [
              {
                id: "focus-critical",
                label: "Focus on Critical",
                type: "danger",
                handler: () => {
                  dashboard.filters.severity = "CRITICAL";
                  dashboard.applyFilters();
                },
              },
              {
                id: "high-exploitation",
                label: "High Exploitation Risk",
                type: "primary",
                handler: () => {
                  dashboard.filters.epssMin = 80;
                  dashboard.applyFilters();
                },
              },
            ],
          });
        }
      },
    });

    // Setup keyboard shortcuts for quick actions
    document.addEventListener("keydown", (event) => {
      if (event.altKey) {
        switch (event.key.toLowerCase()) {
          case "e":
            event.preventDefault();
            this.actions.get("emergency-filter")?.handler();
            break;
          case "s":
            event.preventDefault();
            this.actions.get("siem-export")?.handler();
            break;
          case "r":
            event.preventDefault();
            this.actions.get("risk-summary")?.handler();
            break;
        }
      }
    });
  }
}

/**
 * Alpine.js component for security alerts and quick actions
 */
export function createSecurityComponent() {
  return {
    alertSystem: new SecurityAlertSystem(),
    quickActions: new QuickActionsManager(),
    alerts: [] as SecurityAlert[],
    showAlerts: true,

    init() {
      // Subscribe to alert updates
      this.alertSystem.subscribe((alerts) => {
        this.alerts = alerts;
      });

      // Set up contextual security monitoring
      this.setupSecurityMonitoring();

      // Make globally available
      (window as any).securityAlerts = this.alertSystem;
      (window as any).quickActions = this.quickActions;
    },

    setupSecurityMonitoring() {
      // Monitor for high-risk vulnerability patterns
      // Note: This will be called manually when vulnerabilities change
      const monitorVulnerabilities = (vulns: any[]) => {
        if (!vulns || vulns.length === 0) return;

        const highEpssCount = vulns.filter((v) => v.epssPercentile >= 90).length;
        const recentCritical = vulns.filter((v) => {
          const publishedDate = new Date(v.publishedDate);
          const daysSincePublished = (Date.now() - publishedDate.getTime()) / (1000 * 60 * 60 * 24);
          return v.severity === "CRITICAL" && daysSincePublished <= 7;
        }).length;

        // Alert for newly published critical vulnerabilities
        if (recentCritical > 0) {
          this.alertSystem.addAlert({
            type: "critical",
            title: "New Critical Vulnerabilities Detected",
            message:
              `${recentCritical} critical vulnerabilities published in the last 7 days ` +
              "require immediate attention.",
            priority: 100,
            dismissible: true,
            actions: [
              {
                id: "view-recent-critical",
                label: "View Recent Critical",
                type: "danger",
                handler: () => {
                  const dashboard = (window as any).vulnDashboard;
                  if (dashboard) {
                    dashboard.filters.severity = "CRITICAL";
                    dashboard.filters.publishedDateFrom = new Date(
                      Date.now() - 7 * 24 * 60 * 60 * 1000
                    )
                      .toISOString()
                      .split("T")[0];
                    dashboard.applyFilters();
                  }
                },
              },
            ],
          });
        }

        // Alert for high exploitation probability
        if (highEpssCount > 5) {
          this.alertSystem.addAlert({
            type: "warning",
            title: "High Exploitation Risk Detected",
            message:
              `${highEpssCount} vulnerabilities have EPSS scores ≥ 90%, ` +
              "indicating very high exploitation likelihood.",
            priority: 80,
            dismissible: true,
            actions: [
              {
                id: "focus-high-epss",
                label: "Focus High EPSS",
                type: "primary",
                handler: () => {
                  const dashboard = (window as any).vulnDashboard;
                  if (dashboard) {
                    dashboard.filters.epssMin = 90;
                    dashboard.applyFilters();
                  }
                },
              },
            ],
          });
        }
      };

      // Make monitoring function available for manual calls
      (this as any).monitorVulnerabilities = monitorVulnerabilities;
    },

    toggleAlerts() {
      this.showAlerts = !this.showAlerts;
    },

    dismissAlert(id: string) {
      this.alertSystem.removeAlert(id);
    },

    clearAllAlerts() {
      this.alertSystem.clearAlerts();
    },
  };
}
