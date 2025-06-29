/******/ (() => {
  // webpackBootstrap
  /******/ "use strict";
  /******/ // The require scope
  /******/ var __webpack_require__ = {};
  /******/
  /************************************************************************/
  /******/ /* webpack/runtime/define property getters */
  /******/ (() => {
    /******/ // define getter functions for harmony exports
    /******/ __webpack_require__.d = (exports, definition) => {
      /******/ for (var key in definition) {
        /******/ if (
          __webpack_require__.o(definition, key) &&
          !__webpack_require__.o(exports, key)
        ) {
          /******/ Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
          /******/
        }
        /******/
      }
      /******/
    };
    /******/
  })();
  /******/
  /******/ /* webpack/runtime/hasOwnProperty shorthand */
  /******/ (() => {
    /******/ __webpack_require__.o = (obj, prop) => Object.prototype.hasOwnProperty.call(obj, prop);
    /******/
  })();
  /******/
  /******/ /* webpack/runtime/make namespace object */
  /******/ (() => {
    /******/ // define __esModule on exports
    /******/ __webpack_require__.r = (exports) => {
      /******/ if (typeof Symbol !== "undefined" && Symbol.toStringTag) {
        /******/ Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
        /******/
      }
      /******/ Object.defineProperty(exports, "__esModule", { value: true });
      /******/
    };
    /******/
  })();
  /******/
  /************************************************************************/
  var __webpack_exports__ = {};
  /*!******************************************!*\
  !*** ./src/assets/ts/offline-support.ts ***!
  \******************************************/
  __webpack_require__.r(__webpack_exports__);
  /* harmony export */ __webpack_require__.d(__webpack_exports__, {
    /* harmony export */ CacheManager: () => /* binding */ CacheManager,
    /* harmony export */ OfflineIndicator: () => /* binding */ OfflineIndicator,
    /* harmony export */ OfflineSupport: () => /* binding */ OfflineSupport,
    /* harmony export */ default: () => /* binding */ OfflineSupport,
    /* harmony export */
  });
  /**
   * Offline support and service worker registration
   */
  class OfflineSupport {
    constructor() {
      this.status = {
        supported: "serviceWorker" in navigator,
        registered: false,
        offline: !navigator.onLine,
        updating: false,
      };
      this.listeners = new Map();
      this.init();
    }
    init() {
      if (!this.status.supported) {
        console.warn("Service Worker not supported");
        return;
      }
      this.registerServiceWorker();
      this.setupOnlineOfflineListeners();
      this.setupVisibilityChangeListener();
    }
    async registerServiceWorker() {
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
    setupOnlineOfflineListeners() {
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
    setupVisibilityChangeListener() {
      document.addEventListener("visibilitychange", () => {
        if (!document.hidden && navigator.onLine) {
          this.syncWhenOnline();
        }
      });
    }
    async setupBackgroundSync(registration) {
      try {
        // Background sync is experimental and requires type assertion
        await registration.sync.register("background-sync-vulns");
        console.log("Background sync registered");
      } catch {
        console.log("Background sync not supported or failed to register");
      }
    }
    handleServiceWorkerMessage(data) {
      switch (data.type) {
        case "DATA_UPDATED":
          this.emit("data-updated", data.message);
          break;
        default:
          console.log("Unhandled service worker message:", data);
      }
    }
    async syncWhenOnline() {
      if (!navigator.onLine || !this.status.registered) return;
      try {
        // Trigger background sync if available
        const registration = await navigator.serviceWorker.ready;
        if ("sync" in registration) {
          // Background sync is experimental and requires type assertion
          await registration.sync.register("background-sync-vulns");
        }
      } catch (error) {
        console.log("Background sync trigger failed:", error);
      }
    }
    getStatus() {
      return { ...this.status };
    }
    isOffline() {
      return this.status.offline;
    }
    isSupported() {
      return this.status.supported;
    }
    async updateServiceWorker() {
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
    async skipWaiting() {
      const registration = await navigator.serviceWorker.ready;
      if (registration.waiting) {
        registration.waiting.postMessage({ type: "SKIP_WAITING" });
      }
    }
    // Event system
    on(event, callback) {
      if (!this.listeners.has(event)) {
        this.listeners.set(event, []);
      }
      this.listeners.get(event).push(callback);
    }
    off(event, callback) {
      const callbacks = this.listeners.get(event);
      if (callbacks) {
        const index = callbacks.indexOf(callback);
        if (index > -1) {
          callbacks.splice(index, 1);
        }
      }
    }
    emit(event, data) {
      const callbacks = this.listeners.get(event);
      if (callbacks) {
        callbacks.forEach((callback) => callback(data));
      }
    }
  }
  /**
   * Offline indicator component
   */
  class OfflineIndicator {
    constructor(offlineSupport) {
      this.element = null;
      this.offlineSupport = offlineSupport;
      this.createIndicator();
      this.setupEventListeners();
    }
    createIndicator() {
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
    setupEventListeners() {
      this.offlineSupport.on("offline", () => {
        this.show("You are currently offline. Some features may be limited.");
      });
      this.offlineSupport.on("online", () => {
        this.show("Connection restored. Syncing data...", "success");
        setTimeout(() => this.hide(), 3000);
      });
      this.offlineSupport.on("data-updated", (message) => {
        this.show(message, "info");
        setTimeout(() => this.hide(), 3000);
      });
      this.offlineSupport.on("updateready", () => {
        this.show("New version available. Refresh to update.", "warning");
      });
    }
    show(message, type = "error") {
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
    hide() {
      if (!this.element) return;
      this.element.style.transform = "translateY(-100%)";
    }
  }
  /**
   * Cache management utilities
   */
  class CacheManager {
    static async getCacheSize() {
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
    static async clearCache() {
      if (!("caches" in window)) return;
      const cacheNames = await caches.keys();
      await Promise.all(cacheNames.map((name) => caches.delete(name)));
    }
    static formatBytes(bytes) {
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
    // Export for global access - debugging only
    window.offlineSupport = offlineSupport;
    window.cacheManager = CacheManager;
  });

  /******/
})();
//# sourceMappingURL=offline-support.js.map
