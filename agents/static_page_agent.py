#!/usr/bin/env python3
"""Static page generation agent for creating the Alpine.js dashboard."""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import structlog

from scripts.processing.cache_manager import CacheManager
from scripts.models import Vulnerability


class StaticPageAgent:
    """Agent responsible for generating static pages and dashboard."""
    
    def __init__(
        self,
        cache_dir: Path = Path(".cache"),
        output_dir: Path = Path("public")
    ):
        """Initialize static page agent.
        
        Args:
            cache_dir: Directory for reading cached data
            output_dir: Directory for generated pages
        """
        self.logger = structlog.get_logger(self.__class__.__name__)
        self.cache_dir = cache_dir
        self.output_dir = output_dir
        self.cache_manager = CacheManager(cache_dir)
        
        # Ensure output directories exist
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / "data").mkdir(exist_ok=True)
        (self.output_dir / "api" / "vulns").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "cves").mkdir(exist_ok=True)
        
    async def generate_all(
        self,
        vulnerabilities: List[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate all static pages and data files.
        
        Args:
            vulnerabilities: Optional list of vulnerabilities (fetches from cache if not provided)
            
        Returns:
            Generation results
        """
        start_time = datetime.now()
        
        # Get vulnerabilities from cache if not provided
        if vulnerabilities is None:
            self.logger.info("Loading vulnerabilities from cache")
            cached_vulns = self.cache_manager.get_all_vulnerabilities()
            vulnerabilities = [self._vuln_to_dict(v) for v in cached_vulns]
        
        self.logger.info(f"Generating pages for {len(vulnerabilities)} vulnerabilities")
        
        results = {
            "pages_generated": 0,
            "data_files_generated": 0,
            "errors": []
        }
        
        try:
            # 1. Generate main dashboard using existing script
            self._generate_dashboard()
            results["pages_generated"] += 1
            
            # 2. Generate API data files
            api_results = self._generate_api_files(vulnerabilities)
            results["data_files_generated"] += api_results["files_generated"]
            
            # 3. Generate individual CVE pages
            cve_results = self._generate_cve_pages(vulnerabilities)
            results["pages_generated"] += cve_results["pages_generated"]
            
            # 4. Generate feed files (RSS/Atom)
            feed_results = self._generate_feeds(vulnerabilities)
            results["pages_generated"] += feed_results["feeds_generated"]
            
            # 5. Copy static assets
            self._copy_static_assets()
            
            duration = (datetime.now() - start_time).total_seconds()
            results["duration"] = duration
            results["success"] = True
            
            self.logger.info(
                "Static generation complete",
                pages=results["pages_generated"],
                data_files=results["data_files_generated"],
                duration=duration
            )
            
        except Exception as e:
            self.logger.error(f"Static generation failed: {str(e)}")
            results["success"] = False
            results["errors"].append(str(e))
            
        return results
        
    def _vuln_to_dict(self, vuln: Vulnerability) -> Dict[str, Any]:
        """Convert Vulnerability object to dictionary."""
        return {
            "cve_id": vuln.cve_id,
            "severity": vuln.severity.value if vuln.severity else "UNKNOWN",
            "cvss_base_score": vuln.cvss_base_score,
            "epss_probability": vuln.epss_probability,
            "risk_score": vuln.risk_score,
            "vendor": vuln.vendor,
            "product": vuln.product,
            "attack_vector": vuln.attack_vector,
            "published_date": vuln.published_date.isoformat() if vuln.published_date else None,
            "description": vuln.description,
            "references": vuln.references
        }
        
    def _generate_dashboard(self):
        """Generate main Alpine.js dashboard."""
        self.logger.info("Generating Alpine.js dashboard")
        
        # Use existing generate_alpine_dashboard.py script
        script_path = Path(__file__).parent.parent / "scripts" / "generate_alpine_dashboard.py"
        
        if not script_path.exists():
            raise FileNotFoundError(f"Dashboard generation script not found: {script_path}")
            
        # Run the script
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(f"Dashboard generation failed: {result.stderr}")
            
        self.logger.info("Dashboard generated successfully")
        
    def _generate_api_files(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate API JSON files."""
        self.logger.info("Generating API data files")
        
        results = {"files_generated": 0}
        
        # 1. Generate main index.json
        index_path = self.output_dir / "api" / "vulns" / "index.json"
        with open(index_path, "w") as f:
            json.dump(vulnerabilities, f, separators=(",", ":"))
        results["files_generated"] += 1
        
        # 2. Generate chunked files by severity and year
        chunks = self._chunk_vulnerabilities(vulnerabilities)
        
        for chunk_name, chunk_data in chunks.items():
            chunk_path = self.output_dir / "api" / "vulns" / f"vulns-{chunk_name}.json"
            with open(chunk_path, "w") as f:
                json.dump(chunk_data, f, separators=(",", ":"))
            results["files_generated"] += 1
            
        # 3. Generate chunk index
        chunk_index = {
            "chunks": list(chunks.keys()),
            "total_vulnerabilities": len(vulnerabilities),
            "generated_at": datetime.now().isoformat()
        }
        
        chunk_index_path = self.output_dir / "api" / "vulns" / "chunk-index.json"
        with open(chunk_index_path, "w") as f:
            json.dump(chunk_index, f, indent=2)
        results["files_generated"] += 1
        
        # 4. Generate individual CVE JSON files (for top 100 by risk)
        top_vulns = sorted(vulnerabilities, key=lambda v: v.get("risk_score", 0), reverse=True)[:100]
        
        for vuln in top_vulns:
            cve_path = self.output_dir / "api" / "vulns" / f"{vuln['cve_id']}.json"
            with open(cve_path, "w") as f:
                json.dump(vuln, f, indent=2)
            results["files_generated"] += 1
            
        self.logger.info(f"Generated {results['files_generated']} API files")
        return results
        
    def _chunk_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Chunk vulnerabilities by severity and year."""
        chunks = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN")
            year = "UNKNOWN"
            
            if vuln.get("published_date"):
                try:
                    year = vuln["published_date"][:4]
                except:
                    year = "UNKNOWN"
                    
            chunk_key = f"{year}-{severity}"
            
            if chunk_key not in chunks:
                chunks[chunk_key] = []
                
            chunks[chunk_key].append(vuln)
            
        return chunks
        
    def _generate_cve_pages(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate individual CVE detail pages."""
        self.logger.info("Generating CVE detail pages")
        
        results = {"pages_generated": 0}
        
        # Generate pages for top vulnerabilities by risk score
        top_vulns = sorted(vulnerabilities, key=lambda v: v.get("risk_score", 0), reverse=True)[:500]
        
        for vuln in top_vulns:
            try:
                self._generate_single_cve_page(vuln)
                results["pages_generated"] += 1
            except Exception as e:
                self.logger.warning(f"Failed to generate page for {vuln['cve_id']}: {str(e)}")
                
        self.logger.info(f"Generated {results['pages_generated']} CVE pages")
        return results
        
    def _generate_single_cve_page(self, vuln: Dict[str, Any]):
        """Generate a single CVE detail page."""
        cve_id = vuln["cve_id"]
        cve_dir = self.output_dir / "cves" / cve_id
        cve_dir.mkdir(exist_ok=True)
        
        # Generate HTML page
        html_content = self._generate_cve_html(vuln)
        
        with open(cve_dir / "index.html", "w") as f:
            f.write(html_content)
            
    def _generate_cve_html(self, vuln: Dict[str, Any]) -> str:
        """Generate HTML for a CVE detail page."""
        # Format dates
        published = "Unknown"
        if vuln.get("published_date"):
            try:
                dt = datetime.fromisoformat(vuln["published_date"].replace("Z", "+00:00"))
                published = dt.strftime("%B %d, %Y")
            except:
                published = vuln["published_date"]
                
        # Build references HTML
        references_html = ""
        if vuln.get("references"):
            references_html = "<ul>"
            for ref in vuln["references"][:10]:  # Limit to 10 references
                references_html += f'<li><a href="{ref}" target="_blank" rel="noopener">{ref}</a></li>'
            references_html += "</ul>"
        else:
            references_html = "<p>No references available</p>"
            
        # Severity badge color
        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "orange", 
            "MEDIUM": "yellow",
            "LOW": "blue"
        }
        severity_color = severity_colors.get(vuln.get("severity", "UNKNOWN"), "gray")
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{vuln['cve_id']} - Vulnerability Details</title>
    <meta name="description" content="{vuln.get('description', '')[:160]}">
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-50">
    <div class="container mx-auto px-4 py-8 max-w-4xl">
        <nav class="text-sm mb-4">
            <a href="/vuln-bot/" class="text-blue-600 hover:underline">Home</a> /
            <a href="/vuln-bot/#vulnerabilities" class="text-blue-600 hover:underline">Vulnerabilities</a> /
            <span class="text-gray-600">{vuln['cve_id']}</span>
        </nav>
        
        <div class="bg-white rounded-lg shadow-lg p-6">
            <div class="flex justify-between items-start mb-6">
                <h1 class="text-3xl font-bold">{vuln['cve_id']}</h1>
                <span class="px-3 py-1 text-sm font-semibold text-white bg-{severity_color}-600 rounded">
                    {vuln.get('severity', 'UNKNOWN')}
                </span>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div class="bg-gray-50 p-4 rounded">
                    <div class="text-sm text-gray-600">CVSS Score</div>
                    <div class="text-2xl font-bold">{vuln.get('cvss_base_score', 'N/A')}</div>
                </div>
                <div class="bg-gray-50 p-4 rounded">
                    <div class="text-sm text-gray-600">EPSS Score</div>
                    <div class="text-2xl font-bold">{vuln.get('epss_probability', 0):.1f}%</div>
                </div>
                <div class="bg-gray-50 p-4 rounded">
                    <div class="text-sm text-gray-600">Risk Score</div>
                    <div class="text-2xl font-bold">{vuln.get('risk_score', 0)}</div>
                </div>
                <div class="bg-gray-50 p-4 rounded">
                    <div class="text-sm text-gray-600">Published</div>
                    <div class="text-lg font-semibold">{published}</div>
                </div>
            </div>
            
            <div class="mb-6">
                <h2 class="text-xl font-semibold mb-2">Description</h2>
                <p class="text-gray-700">{vuln.get('description', 'No description available')}</p>
            </div>
            
            <div class="mb-6">
                <h2 class="text-xl font-semibold mb-2">Technical Details</h2>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <span class="font-medium">Attack Vector:</span>
                        <span class="ml-2">{vuln.get('attack_vector', 'None')}</span>
                    </div>
                    <div>
                        <span class="font-medium">Attack Complexity:</span>
                        <span class="ml-2">{vuln.get('attack_complexity', 'Unknown')}</span>
                    </div>
                    <div>
                        <span class="font-medium">Privileges Required:</span>
                        <span class="ml-2">{vuln.get('privileges_required', 'Unknown')}</span>
                    </div>
                    <div>
                        <span class="font-medium">User Interaction:</span>
                        <span class="ml-2">{vuln.get('user_interaction', 'Unknown')}</span>
                    </div>
                </div>
            </div>
            
            <div class="mb-6">
                <h2 class="text-xl font-semibold mb-2">References</h2>
                {references_html}
            </div>
            
            <div class="mt-8 pt-6 border-t">
                <a href="/vuln-bot/" class="text-blue-600 hover:underline">← Back to Dashboard</a>
            </div>
        </div>
    </div>
</body>
</html>"""
        
    def _generate_feeds(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate RSS/Atom feeds."""
        self.logger.info("Generating feeds")
        
        results = {"feeds_generated": 0}
        
        # Sort by published date
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: v.get("published_date", ""),
            reverse=True
        )[:50]  # Latest 50
        
        # Generate Atom feed
        atom_content = self._generate_atom_feed(sorted_vulns)
        with open(self.output_dir / "atom.xml", "w") as f:
            f.write(atom_content)
        results["feeds_generated"] += 1
        
        self.logger.info(f"Generated {results['feeds_generated']} feeds")
        return results
        
    def _generate_atom_feed(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Generate Atom feed content."""
        entries = []
        
        for vuln in vulnerabilities:
            entry = f"""
    <entry>
        <title>{vuln['cve_id']} - {vuln.get('severity', 'UNKNOWN')} - {vuln.get('vendor', 'Unknown')}</title>
        <link href="https://williamzujkowski.github.io/vuln-bot/cves/{vuln['cve_id']}/" />
        <id>https://williamzujkowski.github.io/vuln-bot/cves/{vuln['cve_id']}/</id>
        <published>{vuln.get('published_date', '')}</published>
        <summary>{vuln.get('description', '')[:200]}...</summary>
    </entry>"""
            entries.append(entry)
            
        return f"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
    <title>Vuln-Bot High-Risk CVE Feed</title>
    <link href="https://williamzujkowski.github.io/vuln-bot/atom.xml" rel="self" />
    <link href="https://williamzujkowski.github.io/vuln-bot/" />
    <updated>{datetime.now().isoformat()}</updated>
    <id>https://williamzujkowski.github.io/vuln-bot/</id>
    <author>
        <name>Vuln-Bot</name>
    </author>
    {"".join(entries)}
</feed>"""
        
    def _copy_static_assets(self):
        """Copy static assets if needed."""
        # This is a placeholder for copying any static assets
        # The current implementation embeds everything in the HTML
        pass


# CLI interface
async def main():
    """Main CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate static pages")
    parser.add_argument("--cache-dir", type=Path, default=Path(".cache"))
    parser.add_argument("--output-dir", type=Path, default=Path("public"))
    parser.add_argument("--input", type=Path, help="Optional input JSON file")
    
    args = parser.parse_args()
    
    agent = StaticPageAgent(cache_dir=args.cache_dir, output_dir=args.output_dir)
    
    # Load vulnerabilities if input provided
    vulnerabilities = None
    if args.input:
        with open(args.input) as f:
            data = json.load(f)
            if isinstance(data, list):
                vulnerabilities = data
            elif isinstance(data, dict) and "vulnerabilities" in data:
                vulnerabilities = data["vulnerabilities"]
                
    # Generate all pages
    results = await agent.generate_all(vulnerabilities)
    
    if results["success"]:
        print(f"✅ Static generation complete!")
        print(f"Pages generated: {results['pages_generated']}")
        print(f"Data files generated: {results['data_files_generated']}")
    else:
        print(f"❌ Static generation failed!")
        for error in results["errors"]:
            print(f"  - {error}")


if __name__ == "__main__":
    asyncio.run(main())