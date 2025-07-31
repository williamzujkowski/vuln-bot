/**
 * Image optimization and lazy loading utilities
 */

interface ImageOptimizationConfig {
  rootMargin?: string;
  threshold?: number;
  loadingClass?: string;
  loadedClass?: string;
  errorClass?: string;
}

export class ImageOptimization {
  private observer: IntersectionObserver | null = null;
  private config: Required<ImageOptimizationConfig>;

  constructor(config: ImageOptimizationConfig = {}) {
    this.config = {
      rootMargin: config.rootMargin ?? "50px",
      threshold: config.threshold ?? 0.1,
      loadingClass: config.loadingClass ?? "loading",
      loadedClass: config.loadedClass ?? "loaded",
      errorClass: config.errorClass ?? "error",
    };

    this.init();
  }

  private init(): void {
    if (!("IntersectionObserver" in window)) {
      // Fallback for browsers without IntersectionObserver
      this.loadAllImages();
      return;
    }

    this.observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            this.loadImage(entry.target as HTMLImageElement);
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

  private observeImages(): void {
    const images = document.querySelectorAll('img[loading="lazy"], img[data-src]');
    images.forEach((img) => {
      this.observer?.observe(img);
    });
  }

  private loadImage(img: HTMLImageElement): void {
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

  private loadAllImages(): void {
    const images = document.querySelectorAll("img[data-src]");
    images.forEach((img) => {
      this.loadImage(img as HTMLImageElement);
    });
  }

  public refresh(): void {
    if (this.observer) {
      this.observeImages();
    }
  }

  public destroy(): void {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
  }
}

/**
 * WebP support detection and image format optimization
 */
export class ImageFormatOptimizer {
  private static webpSupported: boolean | null = null;

  static async checkWebPSupport(): Promise<boolean> {
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

  static async optimizeImageSrc(originalSrc: string): Promise<string> {
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

/**
 * Responsive image sizes calculator
 */
export class ResponsiveImageSizes {
  static calculateSizes(breakpoints: Record<string, number> = {}): string {
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

  static generateSrcSet(
    baseSrc: string,
    widths: number[] = [320, 640, 768, 1024, 1280, 1920]
  ): string {
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
export class ImagePerformanceMonitor {
  private static measurements: Map<string, number> = new Map();

  static startMeasurement(imageId: string): void {
    this.measurements.set(imageId, performance.now());
  }

  static endMeasurement(imageId: string): number {
    const startTime = this.measurements.get(imageId);
    if (!startTime) return 0;

    const endTime = performance.now();
    const duration = endTime - startTime;

    this.measurements.delete(imageId);
    return duration;
  }

  static measureImageLoad(img: HTMLImageElement): Promise<number> {
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
export { ImageOptimization as default };
