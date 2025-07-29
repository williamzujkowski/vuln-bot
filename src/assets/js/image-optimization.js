(() => {
  "use strict";
  class s {
    constructor(s = {}) {
      ((this.observer = null),
        (this.config = {
          rootMargin: s.rootMargin ?? "50px",
          threshold: s.threshold ?? 0.1,
          loadingClass: s.loadingClass ?? "loading",
          loadedClass: s.loadedClass ?? "loaded",
          errorClass: s.errorClass ?? "error",
        }),
        this.init());
    }
    init() {
      "IntersectionObserver" in window
        ? ((this.observer = new IntersectionObserver(
            (s) => {
              s.forEach((s) => {
                s.isIntersecting && (this.loadImage(s.target), this.observer?.unobserve(s.target));
              });
            },
            { rootMargin: this.config.rootMargin, threshold: this.config.threshold }
          )),
          this.observeImages())
        : this.loadAllImages();
    }
    observeImages() {
      document.querySelectorAll('img[loading="lazy"], img[data-src]').forEach((s) => {
        this.observer?.observe(s);
      });
    }
    loadImage(s) {
      const e = s.dataset.src ?? s.src;
      if (!e) return;
      s.classList.add(this.config.loadingClass);
      const r = new Image();
      ((r.onload = () => {
        ((s.src = e),
          s.classList.remove(this.config.loadingClass),
          s.classList.add(this.config.loadedClass),
          delete s.dataset.src);
      }),
        (r.onerror = () => {
          (s.classList.remove(this.config.loadingClass),
            s.classList.add(this.config.errorClass),
            console.warn(`Failed to load image: ${e}`));
        }),
        (r.src = e));
    }
    loadAllImages() {
      document.querySelectorAll("img[data-src]").forEach((s) => {
        this.loadImage(s);
      });
    }
    refresh() {
      this.observer && this.observeImages();
    }
    destroy() {
      this.observer && (this.observer.disconnect(), (this.observer = null));
    }
  }
  (new Map(),
    document.addEventListener("DOMContentLoaded", () => {
      const e = new s();
      new MutationObserver(() => {
        e.refresh();
      }).observe(document.body, { childList: !0, subtree: !0 });
    }));
})();
//# sourceMappingURL=image-optimization.js.map
