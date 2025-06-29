#!/usr/bin/env python3
"""Optimize vulnerability storage by using chunked files instead of individual JSONs."""

import json
import shutil
from pathlib import Path
from collections import defaultdict
from typing import Dict, List


def optimize_vulnerability_storage(
    source_dir: Path, output_dir: Path, strategy: str = "severity-year"
):
    """Optimize vulnerability storage using different strategies.

    Args:
        source_dir: Directory containing index.json
        output_dir: Directory for optimized output
        strategy: Storage strategy ('severity-year', 'size-chunks', 'single-file')
    """
    # Read the index file
    index_file = source_dir / "index.json"
    if not index_file.exists():
        print(f"Error: {index_file} not found")
        return

    with open(index_file) as f:
        data = json.load(f)

    vulnerabilities = data["vulnerabilities"]
    print(f"Processing {len(vulnerabilities)} vulnerabilities...")

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    if strategy == "severity-year":
        optimize_by_severity_year(vulnerabilities, output_dir)
    elif strategy == "size-chunks":
        optimize_by_size_chunks(vulnerabilities, output_dir, chunk_size=1000)
    elif strategy == "single-file":
        optimize_single_file(data, output_dir)
    else:
        print(f"Unknown strategy: {strategy}")


def optimize_by_severity_year(vulnerabilities: List[Dict], output_dir: Path):
    """Organize vulnerabilities into chunks by severity and year."""
    chunks = defaultdict(list)

    for vuln in vulnerabilities:
        year = vuln.get("publishedDate", "unknown")[:4]
        severity = vuln.get("severity", "unknown")
        chunk_key = f"{year}-{severity}"
        chunks[chunk_key].append(vuln)

    # Write chunk files
    print(f"\nCreating {len(chunks)} chunk files by severity/year:")
    for chunk_key, chunk_vulns in sorted(chunks.items()):
        output_file = output_dir / f"vulns-{chunk_key}.json"
        chunk_data = {
            "chunk": chunk_key,
            "count": len(chunk_vulns),
            "vulnerabilities": chunk_vulns,
        }
        with open(output_file, "w") as f:
            json.dump(chunk_data, f, indent=2)
        print(f"  - {chunk_key}: {len(chunk_vulns)} vulnerabilities")

    # Create chunk index
    chunk_index = {
        "strategy": "severity-year",
        "total_count": len(vulnerabilities),
        "chunks": [
            {
                "key": chunk_key,
                "file": f"vulns-{chunk_key}.json",
                "count": len(chunk_vulns),
            }
            for chunk_key, chunk_vulns in sorted(chunks.items())
        ],
    }

    with open(output_dir / "chunk-index.json", "w") as f:
        json.dump(chunk_index, f, indent=2)

    print(
        f"\nOptimization complete: {len(chunks)} files instead of {len(vulnerabilities)}"
    )


def optimize_by_size_chunks(
    vulnerabilities: List[Dict], output_dir: Path, chunk_size: int = 1000
):
    """Organize vulnerabilities into fixed-size chunks."""
    chunks = []

    for i in range(0, len(vulnerabilities), chunk_size):
        chunk_num = i // chunk_size + 1
        chunk_vulns = vulnerabilities[i : i + chunk_size]
        chunks.append({"num": chunk_num, "vulns": chunk_vulns})

    # Write chunk files
    print(f"\nCreating {len(chunks)} fixed-size chunks ({chunk_size} vulns each):")
    for chunk in chunks:
        output_file = output_dir / f"vulns-chunk-{chunk['num']:03d}.json"
        chunk_data = {
            "chunk": chunk["num"],
            "count": len(chunk["vulns"]),
            "vulnerabilities": chunk["vulns"],
        }
        with open(output_file, "w") as f:
            json.dump(chunk_data, f, indent=2)
        print(f"  - Chunk {chunk['num']}: {len(chunk['vulns'])} vulnerabilities")

    print(
        f"\nOptimization complete: {len(chunks)} files instead of {len(vulnerabilities)}"
    )


def optimize_single_file(data: Dict, output_dir: Path):
    """Keep everything in a single enhanced index file."""
    # Add full details to each vulnerability if not present
    enhanced_data = {
        **data,
        "storage_strategy": "single-file",
        "includes_full_details": True,
    }

    output_file = output_dir / "vulns-complete.json"
    with open(output_file, "w") as f:
        json.dump(enhanced_data, f, indent=2)

    print(f"\nOptimization complete: 1 file with all {data['count']} vulnerabilities")


def create_client_viewer():
    """Generate a client-side JSON viewer component."""
    viewer_code = """
// Vulnerability Detail Viewer Component
class VulnerabilityViewer {
    constructor() {
        this.modal = null;
    }

    show(vulnerability) {
        // Remove existing modal if any
        if (this.modal) {
            this.modal.remove();
        }

        // Create modal element
        this.modal = document.createElement('div');
        this.modal.className = 'vuln-detail-modal';
        this.modal.innerHTML = `
            <div class="modal-backdrop" onclick="vulnViewer.close()"></div>
            <div class="modal-content">
                <div class="modal-header">
                    <h2>${vulnerability.cveId}</h2>
                    <button class="modal-close" onclick="vulnViewer.close()">×</button>
                </div>
                <div class="modal-body">
                    <pre class="json-viewer">${JSON.stringify(vulnerability, null, 2)}</pre>
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

    copyToClipboard() {
        const json = JSON.stringify(this.currentVuln, null, 2);
        navigator.clipboard.writeText(json).then(() => {
            alert('Copied to clipboard!');
        });
    }

    download() {
        const json = JSON.stringify(this.currentVuln, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${this.currentVuln.cveId}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }
}

// Initialize global viewer instance
const vulnViewer = new VulnerabilityViewer();

// Add CSS for the modal
const style = document.createElement('style');
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
    }

    .modal-content {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: white;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
        max-width: 80%;
        max-height: 80%;
        overflow: hidden;
        display: flex;
        flex-direction: column;
    }

    .modal-header {
        padding: 1rem;
        border-bottom: 1px solid #eee;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }

    .modal-body {
        flex: 1;
        overflow: auto;
        padding: 1rem;
    }

    .modal-footer {
        padding: 1rem;
        border-top: 1px solid #eee;
        display: flex;
        gap: 0.5rem;
        justify-content: flex-end;
    }

    .json-viewer {
        background: #f5f5f5;
        padding: 1rem;
        border-radius: 4px;
        overflow: auto;
        font-family: monospace;
        font-size: 0.875rem;
    }

    .modal-close {
        background: none;
        border: none;
        font-size: 1.5rem;
        cursor: pointer;
        padding: 0;
        width: 2rem;
        height: 2rem;
    }
`;
document.head.appendChild(style);
"""

    return viewer_code


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python storage_optimizer.py <source_dir> <output_dir> [strategy]")
        print("Strategies: severity-year (default), size-chunks, single-file")
        sys.exit(1)

    source_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    strategy = sys.argv[3] if len(sys.argv) > 3 else "severity-year"

    optimize_vulnerability_storage(source_dir, output_dir, strategy)

    # Also generate the client viewer code
    viewer_file = output_dir / "vulnerability-viewer.js"
    with open(viewer_file, "w") as f:
        f.write(create_client_viewer())
    print(f"\nGenerated client-side viewer: {viewer_file}")