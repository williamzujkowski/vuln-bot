/**
 * Offline support and service worker registration
 */

interface ServiceWorkerStatus {
  supported: boolean;
  registered: boolean;
  offline: boolean;
  updating: boolean;
}

export class OfflineSupport {
  private status: ServiceWorkerStatus = {
    supported: "serviceWorker" in navigator,
    registered: false,
    offline: !navigator.onLine,
    updating: false,
  };

  private listeners: Map<string, Function[]> = new Map();

  constructor() {
    this.init();
  }

  private init(): void {
    if (!this.status.supported) {
      console.warn("Service Worker not supported");
      return;
    }

    this.registerServiceWorker();
    this.setupOnlineOfflineListeners();
    this.setupVisibilityChangeListener();
  }

  private async registerServiceWorker(): Promise<void> {
    try {
      const registration = await navigator.serviceWorker.register(
        "/vuln-bot/assets/js/service-worker.js",
        {
          scope: "/vuln-bot/",
        }
      );

      console.log("Service Worker registered successfully");
      this.status.registered = true;
      this.emit("registered", registration);

      // Listen for service worker updates
      registration.addEventListener("updatefound", () => {
        this.status.updating = true;
        this.emit("updatefound");

        const newWorker = registration.installing;
        if (newWorker) {
          newWorker.addEventListener("statechange", () => {
            if (newWorker.state === "installed" && navigator.serviceWorker.controller) {
              this.status.updating = false;
              this.emit("updateready");
            }
          });
        }
      });

      // Listen for service worker messages
      navigator.serviceWorker.addEventListener("message", (event) => {
        this.handleServiceWorkerMessage(event.data);
      });

      // Register for background sync (if supported)
      if ("sync" in registration) {
        this.setupBackgroundSync(registration);
      }
    } catch (error) {
      console.error("Service Worker registration failed:", error);
      this.emit("error", error);
    }
  }

  private setupOnlineOfflineListeners(): void {
    window.addEventListener("online", () => {
      this.status.offline = false;
      this.emit("online");
      this.syncWhenOnline();
    });

    window.addEventListener("offline", () => {
      this.status.offline = true;
      this.emit("offline");
    });
  }

  private setupVisibilityChangeListener(): void {
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden && navigator.onLine) {
        this.syncWhenOnline();
      }
    });
  }

  private async setupBackgroundSync(registration: ServiceWorkerRegistration): Promise<void> {
    try {
      await (registration as any).sync.register("background-sync-vulns");
      console.log("Background sync registered");
    } catch {
      console.log("Background sync not supported or failed to register");
    }
  }

  private handleServiceWorkerMessage(data: any): void {
    switch (data.type) {
      case "DATA_UPDATED":
        this.emit("data-updated", data.message);
        break;
      default:
        console.log("Unhandled service worker message:", data);
    }
  }

  private async syncWhenOnline(): Promise<void> {
    if (!navigator.onLine || !this.status.registered) return;

    try {
      // Trigger background sync if available
      const registration = await navigator.serviceWorker.ready;
      if ("sync" in registration) {
        await (registration as any).sync.register("background-sync-vulns");
      }
    } catch (error) {
      console.log("Background sync trigger failed:", error);
    }
  }

  public getStatus(): ServiceWorkerStatus {
    return { ...this.status };
  }

  public isOffline(): boolean {
    return this.status.offline;
  }

  public isSupported(): boolean {
    return this.status.supported;
  }

  public async updateServiceWorker(): Promise<void> {
    if (!this.status.registered) return;

    try {
      const registration = await navigator.serviceWorker.ready;
      await registration.update();
      this.emit("update-triggered");
    } catch (error) {
      console.error("Service worker update failed:", error);
      this.emit("error", error);
    }
  }

  public async skipWaiting(): Promise<void> {
    const registration = await navigator.serviceWorker.ready;
    if (registration.waiting) {
      registration.waiting.postMessage({ type: "SKIP_WAITING" });
    }
  }

  // Event system
  public on(event: string, callback: Function): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(callback);
  }

  public off(event: string, callback: Function): void {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }

  private emit(event: string, data?: any): void {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.forEach((callback) => callback(data));
    }
  }
}

/**
 * Offline indicator component
 */
export class OfflineIndicator {
  private element: HTMLElement | null = null;
  private offlineSupport: OfflineSupport;

  constructor(offlineSupport: OfflineSupport) {
    this.offlineSupport = offlineSupport;
    this.createIndicator();
    this.setupEventListeners();
  }

  private createIndicator(): void {
    this.element = document.createElement("div");
    this.element.id = "offline-indicator";
    this.element.className = "offline-indicator";
    this.element.setAttribute("role", "status");
    this.element.setAttribute("aria-live", "polite");
    this.element.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background: #dc2626;
      color: white;
      text-align: center;
      padding: 8px;
      font-size: 14px;
      transform: translateY(-100%);
      transition: transform 0.3s ease;
      z-index: 9999;
    `;

    document.body.appendChild(this.element);
  }

  private setupEventListeners(): void {
    this.offlineSupport.on("offline", () => {
      this.show("You are currently offline. Some features may be limited.");
    });

    this.offlineSupport.on("online", () => {
      this.show("Connection restored. Syncing data...", "success");
      setTimeout(() => this.hide(), 3000);
    });

    this.offlineSupport.on("data-updated", (message: string) => {
      this.show(message, "info");
      setTimeout(() => this.hide(), 3000);
    });

    this.offlineSupport.on("updateready", () => {
      this.show("New version available. Refresh to update.", "warning");
    });
  }

  private show(message: string, type: "error" | "success" | "info" | "warning" = "error"): void {
    if (!this.element) return;

    const colors = {
      error: "#dc2626",
      success: "#10b981",
      info: "#2563eb",
      warning: "#f59e0b",
    };

    this.element.textContent = message;
    this.element.style.backgroundColor = colors[type];
    this.element.style.transform = "translateY(0)";
  }

  private hide(): void {
    if (!this.element) return;
    this.element.style.transform = "translateY(-100%)";
  }
}

/**
 * Cache management utilities
 */
export class CacheManager {
  static async getCacheSize(): Promise<number> {
    if (!("caches" in window)) return 0;

    let totalSize = 0;
    const cacheNames = await caches.keys();

    for (const name of cacheNames) {
      const cache = await caches.open(name);
      const keys = await cache.keys();

      for (const request of keys) {
        const response = await cache.match(request);
        if (response) {
          const blob = await response.blob();
          totalSize += blob.size;
        }
      }
    }

    return totalSize;
  }

  static async clearCache(): Promise<void> {
    if (!("caches" in window)) return;

    const cacheNames = await caches.keys();
    await Promise.all(cacheNames.map((name) => caches.delete(name)));
  }

  static formatBytes(bytes: number): string {
    if (bytes === 0) return "0 Bytes";

    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }
}

// Initialize offline support when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
  const offlineSupport = new OfflineSupport();
  new OfflineIndicator(offlineSupport);

  // Expose to global scope for debugging
  (window as any).offlineSupport = offlineSupport;
  (window as any).cacheManager = CacheManager;
});

export { OfflineSupport as default };
