/**
 * Global window type extensions
 */

interface VulnerabilityViewer {
  show(vulnerability: any): void;
  close(): void;
  copyToClipboard(): void;
  download(): void;
}

interface Window {
  vulnViewer: VulnerabilityViewer;
}