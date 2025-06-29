(() => {
  "use strict";
  class e {
    constructor() {
      ((this.status = {
        supported: "serviceWorker" in navigator,
        registered: !1,
        offline: !navigator.onLine,
        updating: !1,
      }),
        (this.listeners = new Map()),
        this.init());
    }
    init() {
      this.status.supported
        ? (this.registerServiceWorker(),
          this.setupOnlineOfflineListeners(),
          this.setupVisibilityChangeListener())
        : console.warn("Service Worker not supported");
    }
    async registerServiceWorker() {
      try {
        const e = await navigator.serviceWorker.register("/vuln-bot/assets/js/service-worker.js", {
          scope: "/vuln-bot/",
        });
        (console.log("Service Worker registered successfully"),
          (this.status.registered = !0),
          this.emit("registered", e),
          e.addEventListener("updatefound", () => {
            ((this.status.updating = !0), this.emit("updatefound"));
            const t = e.installing;
            t &&
              t.addEventListener("statechange", () => {
                "installed" === t.state &&
                  navigator.serviceWorker.controller &&
                  ((this.status.updating = !1), this.emit("updateready"));
              });
          }),
          navigator.serviceWorker.addEventListener("message", (e) => {
            this.handleServiceWorkerMessage(e.data);
          }),
          "sync" in e && this.setupBackgroundSync(e));
      } catch (e) {
        (console.error("Service Worker registration failed:", e), this.emit("error", e));
      }
    }
    setupOnlineOfflineListeners() {
      (window.addEventListener("online", () => {
        ((this.status.offline = !1), this.emit("online"), this.syncWhenOnline());
      }),
        window.addEventListener("offline", () => {
          ((this.status.offline = !0), this.emit("offline"));
        }));
    }
    setupVisibilityChangeListener() {
      document.addEventListener("visibilitychange", () => {
        !document.hidden && navigator.onLine && this.syncWhenOnline();
      });
    }
    async setupBackgroundSync(e) {
      try {
        (await e.sync.register("background-sync-vulns"), console.log("Background sync registered"));
      } catch {
        console.log("Background sync not supported or failed to register");
      }
    }
    handleServiceWorkerMessage(e) {
      "DATA_UPDATED" === e.type
        ? this.emit("data-updated", e.message)
        : console.log("Unhandled service worker message:", e);
    }
    async syncWhenOnline() {
      if (navigator.onLine && this.status.registered)
        try {
          const e = await navigator.serviceWorker.ready;
          "sync" in e && (await e.sync.register("background-sync-vulns"));
        } catch (e) {
          console.log("Background sync trigger failed:", e);
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
      if (this.status.registered)
        try {
          const e = await navigator.serviceWorker.ready;
          (await e.update(), this.emit("update-triggered"));
        } catch (e) {
          (console.error("Service worker update failed:", e), this.emit("error", e));
        }
    }
    async skipWaiting() {
      const e = await navigator.serviceWorker.ready;
      e.waiting && e.waiting.postMessage({ type: "SKIP_WAITING" });
    }
    on(e, t) {
      (this.listeners.has(e) || this.listeners.set(e, []), this.listeners.get(e).push(t));
    }
    off(e, t) {
      const s = this.listeners.get(e);
      if (s) {
        const e = s.indexOf(t);
        e > -1 && s.splice(e, 1);
      }
    }
    emit(e, t) {
      const s = this.listeners.get(e);
      s && s.forEach((e) => e(t));
    }
  }
  class t {
    constructor(e) {
      ((this.element = null),
        (this.offlineSupport = e),
        this.createIndicator(),
        this.setupEventListeners());
    }
    createIndicator() {
      ((this.element = document.createElement("div")),
        (this.element.id = "offline-indicator"),
        (this.element.className = "offline-indicator"),
        this.element.setAttribute("role", "status"),
        this.element.setAttribute("aria-live", "polite"),
        (this.element.style.cssText =
          "\n      position: fixed;\n      top: 0;\n      left: 0;\n      right: 0;\n      background: #dc2626;\n      color: white;\n      text-align: center;\n      padding: 8px;\n      font-size: 14px;\n      transform: translateY(-100%);\n      transition: transform 0.3s ease;\n      z-index: 9999;\n    "),
        document.body.appendChild(this.element));
    }
    setupEventListeners() {
      (this.offlineSupport.on("offline", () => {
        this.show("You are currently offline. Some features may be limited.");
      }),
        this.offlineSupport.on("online", () => {
          (this.show("Connection restored. Syncing data...", "success"),
            setTimeout(() => this.hide(), 3e3));
        }),
        this.offlineSupport.on("data-updated", (e) => {
          (this.show(e, "info"), setTimeout(() => this.hide(), 3e3));
        }),
        this.offlineSupport.on("updateready", () => {
          this.show("New version available. Refresh to update.", "warning");
        }));
    }
    show(e, t = "error") {
      this.element &&
        ((this.element.textContent = e),
        (this.element.style.backgroundColor = {
          error: "#dc2626",
          success: "#10b981",
          info: "#2563eb",
          warning: "#f59e0b",
        }[t]),
        (this.element.style.transform = "translateY(0)"));
    }
    hide() {
      this.element && (this.element.style.transform = "translateY(-100%)");
    }
  }
  class s {
    static async getCacheSize() {
      if (!("caches" in window)) return 0;
      let e = 0;
      const t = await caches.keys();
      for (const s of t) {
        const t = await caches.open(s),
          i = await t.keys();
        for (const s of i) {
          const i = await t.match(s);
          i && (e += (await i.blob()).size);
        }
      }
      return e;
    }
    static async clearCache() {
      if (!("caches" in window)) return;
      const e = await caches.keys();
      await Promise.all(e.map((e) => caches.delete(e)));
    }
    static formatBytes(e) {
      if (0 === e) return "0 Bytes";
      const t = Math.floor(Math.log(e) / Math.log(1024));
      return parseFloat((e / Math.pow(1024, t)).toFixed(2)) + " " + ["Bytes", "KB", "MB", "GB"][t];
    }
  }
  document.addEventListener("DOMContentLoaded", () => {
    const i = new e();
    (new t(i), (window.offlineSupport = i), (window.cacheManager = s));
  });
})();
//# sourceMappingURL=offline-support.js.map
