/**
 * Global window type extensions
 */

interface Vulnerability {
  cveId: string;
  descriptions?: Array<{
    lang: string;
    value: string;
  }>;
  published?: string;
  lastModified?: string;
  vulnStatus?: string;
  [key: string]: unknown;
}

interface VulnerabilityViewer {
  show(vulnerability: Vulnerability): void;
  close(): void;
  copyToClipboard(): void;
  download(): void;
}

interface Window {
  vulnViewer: VulnerabilityViewer;
}
