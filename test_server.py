#!/usr/bin/env python3
"""Simple HTTP server to test the site locally."""

import http.server
import socketserver
import os

# Change to the public directory
os.chdir('public')

PORT = 8080
Handler = http.server.SimpleHTTPRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Server running at http://localhost:{PORT}")
    print("Press Ctrl-C to stop")
    httpd.serve_forever()