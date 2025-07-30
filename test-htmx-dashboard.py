#!/usr/bin/env python3
"""
Test the HTMX dashboard locally
"""

import subprocess
import webbrowser
import time
from pathlib import Path

def main():
    print("🚀 Testing HTMX Dashboard")
    
    # Check if public/index.html exists
    if not Path("public/index.html").exists():
        print("❌ Dashboard not generated yet")
        print("   The dashboard will be generated automatically by GitHub Actions")
        print("   after the first harvest run")
        return
    
    # Start a simple HTTP server
    port = 8080
    print(f"🌐 Starting local server on http://localhost:{port}")
    print("📝 Press Ctrl+C to stop")
    
    # Open browser
    time.sleep(1)
    webbrowser.open(f"http://localhost:{port}")
    
    # Start server
    try:
        subprocess.run(["python", "-m", "http.server", str(port), "--directory", "public"])
    except KeyboardInterrupt:
        print("\n✅ Server stopped")

if __name__ == "__main__":
    main()