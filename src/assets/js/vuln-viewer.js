// Vulnerability Detail Viewer Component
class VulnerabilityViewer {
  constructor() {
    this.modal = null;
    this.currentVuln = null;
  }

  show(vulnerability) {
    // Remove existing modal if any
    if (this.modal) {
      this.modal.remove();
    }

    // Create modal element
    this.modal = document.createElement("div");
    this.modal.className = "vuln-detail-modal";
    this.modal.innerHTML = `
            <div class="modal-backdrop" onclick="vulnViewer.close()"></div>
            <div class="modal-content">
                <div class="modal-header">
                    <h2>${vulnerability.cveId}</h2>
                    <button class="modal-close" onclick="vulnViewer.close()">×</button>
                </div>
                <div class="modal-body">
                    <pre class="json-viewer">${this.formatJSON(vulnerability)}</pre>
                </div>
                <div class="modal-footer">
                    <button onclick="vulnViewer.copyToClipboard()">Copy JSON</button>
                    <button onclick="vulnViewer.download()">Download</button>
                </div>
            </div>
        `;

    document.body.appendChild(this.modal);
    this.currentVuln = vulnerability;
  }

  close() {
    if (this.modal) {
      this.modal.remove();
      this.modal = null;
    }
  }

  formatJSON(obj) {
    return JSON.stringify(obj, null, 2)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  copyToClipboard() {
    const json = JSON.stringify(this.currentVuln, null, 2);
    navigator.clipboard
      .writeText(json)
      .then(() => {
        // Show brief success message
        const button = event.target;
        const originalText = button.textContent;
        button.textContent = "Copied!";
        setTimeout(() => {
          button.textContent = originalText;
        }, 2000);
      })
      .catch((err) => {
        console.error("Failed to copy:", err);
        alert("Failed to copy to clipboard");
      });
  }

  download() {
    const json = JSON.stringify(this.currentVuln, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${this.currentVuln.cveId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
}

// Initialize global viewer instance
window.vulnViewer = new VulnerabilityViewer();

// Add CSS for the modal
const style = document.createElement("style");
style.textContent = `
    .vuln-detail-modal {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 1000;
    }

    .modal-backdrop {
        position: absolute;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(2px);
    }

    .modal-content {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: var(--color-bg-primary);
        border-radius: var(--radius-lg);
        box-shadow: var(--shadow-xl);
        max-width: 80%;
        max-height: 80%;
        overflow: hidden;
        display: flex;
        flex-direction: column;
    }

    .modal-header {
        padding: var(--space-4);
        border-bottom: 1px solid var(--color-border);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .modal-header h2 {
        margin: 0;
        font-size: 1.25rem;
        color: var(--color-text-primary);
    }

    .modal-body {
        flex: 1;
        overflow: auto;
        padding: var(--space-4);
    }

    .modal-footer {
        padding: var(--space-4);
        border-top: 1px solid var(--color-border);
        display: flex;
        gap: var(--space-2);
        justify-content: flex-end;
    }

    .modal-footer button {
        padding: var(--space-2) var(--space-4);
        background: var(--color-primary);
        color: white;
        border: none;
        border-radius: var(--radius);
        cursor: pointer;
        font-size: 0.875rem;
        transition: background-color 0.2s;
    }

    .modal-footer button:hover {
        background: var(--color-primary-dark);
    }

    .json-viewer {
        background: var(--color-bg-secondary);
        padding: var(--space-4);
        border-radius: var(--radius);
        overflow: auto;
        font-family: 'SF Mono', Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
        font-size: 0.875rem;
        line-height: 1.5;
        color: var(--color-text-primary);
    }

    .modal-close {
        background: none;
        border: none;
        font-size: 1.5rem;
        cursor: pointer;
        padding: 0;
        width: 2rem;
        height: 2rem;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: var(--radius);
        color: var(--color-text-secondary);
        transition: background-color 0.2s;
    }

    .modal-close:hover {
        background: var(--color-bg-secondary);
    }

    @media (max-width: 768px) {
        .modal-content {
            max-width: 95%;
            max-height: 95%;
        }
    }
`;
document.head.appendChild(style);
