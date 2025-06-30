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
  /*!*********************************************!*\
  !*** ./src/assets/ts/image-optimization.ts ***!
  \*********************************************/
  __webpack_require__.r(__webpack_exports__);
  /* harmony export */ __webpack_require__.d(__webpack_exports__, {
    /* harmony export */ ImageFormatOptimizer: () => /* binding */ ImageFormatOptimizer,
    /* harmony export */ ImageOptimization: () => /* binding */ ImageOptimization,
    /* harmony export */ ImagePerformanceMonitor: () => /* binding */ ImagePerformanceMonitor,
    /* harmony export */ ResponsiveImageSizes: () => /* binding */ ResponsiveImageSizes,
    /* harmony export */ default: () => /* binding */ ImageOptimization,
    /* harmony export */
  });
  /**
   * Image optimization and lazy loading utilities
   */
  class ImageOptimization {
    constructor(config = {}) {
      this.observer = null;
      this.config = {
        rootMargin: config.rootMargin ?? "50px",
        threshold: config.threshold ?? 0.1,
        loadingClass: config.loadingClass ?? "loading",
        loadedClass: config.loadedClass ?? "loaded",
        errorClass: config.errorClass ?? "error",
      };
      this.init();
    }
    init() {
      if (!("IntersectionObserver" in window)) {
        // Fallback for browsers without IntersectionObserver
        this.loadAllImages();
        return;
      }
      this.observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) {
              this.loadImage(entry.target);
              this.observer?.unobserve(entry.target);
            }
          });
        },
        {
          rootMargin: this.config.rootMargin,
          threshold: this.config.threshold,
        }
      );
      this.observeImages();
    }
    observeImages() {
      const images = document.querySelectorAll('img[loading="lazy"], img[data-src]');
      images.forEach((img) => {
        this.observer?.observe(img);
      });
    }
    loadImage(img) {
      const src = img.dataset.src ?? img.src;
      if (!src) return;
      img.classList.add(this.config.loadingClass);
      // Create a new image to preload
      const imageLoader = new Image();
      imageLoader.onload = () => {
        img.src = src;
        img.classList.remove(this.config.loadingClass);
        img.classList.add(this.config.loadedClass);
        // Remove data-src to prevent reloading
        delete img.dataset.src;
      };
      imageLoader.onerror = () => {
        img.classList.remove(this.config.loadingClass);
        img.classList.add(this.config.errorClass);
        console.warn(`Failed to load image: ${src}`);
      };
      imageLoader.src = src;
    }
    loadAllImages() {
      const images = document.querySelectorAll("img[data-src]");
      images.forEach((img) => {
        this.loadImage(img);
      });
    }
    refresh() {
      if (this.observer) {
        this.observeImages();
      }
    }
    destroy() {
      if (this.observer) {
        this.observer.disconnect();
        this.observer = null;
      }
    }
  }
  /**
   * WebP support detection and image format optimization
   */
  class ImageFormatOptimizer {
    static async checkWebPSupport() {
      if (this.webpSupported !== null) {
        return this.webpSupported;
      }
      return new Promise((resolve) => {
        const webp = new Image();
        webp.onload = webp.onerror = () => {
          this.webpSupported = webp.height === 2;
          resolve(this.webpSupported);
        };
        webp.src =
          "data:image/webp;base64,UklGRjoAAABXRUJQVlA4IC4AAACyAgCdASoCAAIALmk0mk0iIiIiIgBoSygABc6WWgAA/veff/0PP8bA//LwYAAA";
      });
    }
    static async optimizeImageSrc(originalSrc) {
      const webpSupported = await this.checkWebPSupport();
      if (webpSupported && !originalSrc.includes(".webp")) {
        // Try to get WebP version
        const webpSrc = originalSrc.replace(/\.(jpg|jpeg|png)$/i, ".webp");
        // Check if WebP version exists
        return new Promise((resolve) => {
          const img = new Image();
          img.onload = () => resolve(webpSrc);
          img.onerror = () => resolve(originalSrc);
          img.src = webpSrc;
        });
      }
      return originalSrc;
    }
  }
  ImageFormatOptimizer.webpSupported = null;
  /**
   * Responsive image sizes calculator
   */
  class ResponsiveImageSizes {
    static calculateSizes(breakpoints = {}) {
      const defaultBreakpoints = {
        sm: 640,
        md: 768,
        lg: 1024,
        xl: 1280,
        ...breakpoints,
      };
      const sizes = [];
      // Mobile first approach
      sizes.push("100vw");
      // Add breakpoint-specific sizes
      Object.entries(defaultBreakpoints)
        .sort(([, a], [, b]) => a - b)
        .forEach(([name, width]) => {
          if (name === "sm") {
            sizes.unshift("(max-width: 640px) 100vw");
          } else if (name === "md") {
            sizes.unshift("(max-width: 768px) 50vw");
          } else if (name === "lg") {
            sizes.unshift("(max-width: 1024px) 33vw");
          } else {
            sizes.unshift(`(max-width: ${width}px) 25vw`);
          }
        });
      return sizes.join(", ");
    }
    static generateSrcSet(baseSrc, widths = [320, 640, 768, 1024, 1280, 1920]) {
      return widths
        .map((width) => {
          const src = baseSrc.replace(/(\.[^.]+)$/, `_${width}w$1`);
          return `${src} ${width}w`;
        })
        .join(", ");
    }
  }
  /**
   * Image performance monitoring
   */
  class ImagePerformanceMonitor {
    static startMeasurement(imageId) {
      this.measurements.set(imageId, performance.now());
    }
    static endMeasurement(imageId) {
      const startTime = this.measurements.get(imageId);
      if (!startTime) return 0;
      const endTime = performance.now();
      const duration = endTime - startTime;
      this.measurements.delete(imageId);
      return duration;
    }
    static measureImageLoad(img) {
      return new Promise((resolve) => {
        const startTime = performance.now();
        const onLoad = () => {
          const duration = performance.now() - startTime;
          img.removeEventListener("load", onLoad);
          img.removeEventListener("error", onError);
          resolve(duration);
        };
        const onError = () => {
          const duration = performance.now() - startTime;
          img.removeEventListener("load", onLoad);
          img.removeEventListener("error", onError);
          resolve(duration);
        };
        if (img.complete) {
          resolve(0);
        } else {
          img.addEventListener("load", onLoad);
          img.addEventListener("error", onError);
        }
      });
    }
  }
  ImagePerformanceMonitor.measurements = new Map();
  // Initialize image optimization when DOM is ready
  document.addEventListener("DOMContentLoaded", () => {
    const imageOptimizer = new ImageOptimization();
    // Re-observe images when new content is added dynamically
    const observer = new MutationObserver(() => {
      imageOptimizer.refresh();
    });
    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  });
  // Export for use in other modules

  /******/
})();
//# sourceMappingURL=image-optimization.js.map
