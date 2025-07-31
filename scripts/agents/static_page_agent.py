"""Static Page Agent - Generates static CVE detail pages using Eleventy."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

from scripts.agents.base_agent import BaseAgent
from scripts.processing.cache_manager import CacheManager


class StaticPageAgent(BaseAgent):
    """Agent responsible for generating static CVE detail pages."""
    
    def __init__(self, cache_dir: Path = None):
        super().__init__("static_page", cache_dir)
        self.cache_manager = None
        
        # Configuration
        self.config = {
            'output_dir': 'src/cves',
            'template_format': 'md',
            'max_pages_per_run': 500,
            'include_full_details': True,
            'generate_index': True
        }
    
    async def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute static page generation.
        
        Returns:
            Results from static page generation
        """
        # Initialize cache manager
        if not self.cache_manager:
            cache_db_path = self.cache_dir / "vulns.db"
            self.cache_manager = CacheManager(db_path=str(cache_db_path))
        
        config = {**self.config, **kwargs}
        output_dir = Path(config['output_dir'])
        
        results = {
            'started_at': datetime.now(timezone.utc).isoformat(),
            'config': config,
            'pages_generated': 0,
            'pages_updated': 0,
            'pages_skipped': 0,
            'success': True,
            'errors': []
        }
        
        try:
            # Ensure output directory exists
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Get recent vulnerabilities from cache
            vulnerabilities = await asyncio.to_thread(
                self.cache_manager.get_recent_vulnerabilities,
                limit=config['max_pages_per_run']
            )
            
            self.logger.info(
                "Generating static pages",
                vulnerability_count=len(vulnerabilities),
                output_dir=str(output_dir)
            )
            
            # Track existing files for cleanup
            existing_files = set(output_dir.glob("CVE-*.md"))
            current_files = set()
            
            # Generate pages for each vulnerability
            for vuln in vulnerabilities:
                try:
                    page_path = output_dir / f"{vuln.cve_id}.md"
                    current_files.add(page_path)
                    
                    # Check if page needs updating
                    should_update = True
                    if page_path.exists():
                        try:
                            existing_content = page_path.read_text()
                            if f"last_modified: {vuln.last_modified_date.isoformat()}" in existing_content:
                                should_update = False
                                results['pages_skipped'] += 1
                        except Exception:
                            pass  # If we can't read, regenerate
                    
                    if should_update:
                        # Generate page content
                        page_content = await self._generate_page_content(vuln, config)
                        
                        # Write page
                        page_path.write_text(page_content)
                        
                        if page_path in existing_files:
                            results['pages_updated'] += 1
                        else:
                            results['pages_generated'] += 1
                        
                        self.logger.debug("Generated page", cve_id=vuln.cve_id, path=str(page_path))
                    
                except Exception as e:
                    error_msg = f"Failed to generate page for {vuln.cve_id}: {str(e)}"
                    results['errors'].append(error_msg)
                    self.logger.error(error_msg)
            
            # Clean up obsolete files
            obsolete_files = existing_files - current_files
            for obsolete_file in obsolete_files:
                try:
                    obsolete_file.unlink()
                    self.logger.debug("Removed obsolete page", path=str(obsolete_file))
                except Exception as e:
                    self.logger.warning("Failed to remove obsolete page", path=str(obsolete_file), error=str(e))
            
            # Generate index page if requested
            if config.get('generate_index'):
                await self._generate_index_page(vulnerabilities, output_dir, config)
            
            results['obsolete_files_removed'] = len(obsolete_files)
            results['completed_at'] = datetime.now(timezone.utc).isoformat()
            
            self.logger.info(
                "Static page generation completed",
                pages_generated=results['pages_generated'],
                pages_updated=results['pages_updated'],
                pages_skipped=results['pages_skipped'],
                obsolete_removed=results['obsolete_files_removed']
            )
            
            return results
            
        except Exception as e:
            results['success'] = False
            results['errors'].append(str(e))
            results['completed_at'] = datetime.now(timezone.utc).isoformat()
            
            self.logger.error("Static page generation failed", error=str(e))
            raise
    
    async def _generate_page_content(self, vuln, config: Dict[str, Any]) -> str:
        """Generate content for a single CVE page.
        
        Args:
            vuln: Vulnerability object
            config: Generation configuration
            
        Returns:
            Page content as string
        """
        # Extract comprehensive data
        vuln_dict = vuln.to_detail_dict()
        
        # Add computed fields
        vuln_dict['enhanced_title'] = vuln._create_enhanced_title()
        vuln_dict['cwe_ids'] = vuln.cwe_ids
        vuln_dict['comprehensive_cvss'] = vuln.comprehensive_cvss_metrics
        
        # YAML frontmatter
        frontmatter = {
            'layout': 'cve-detail',
            'cve_id': vuln.cve_id,
            'title': vuln_dict['enhanced_title'],
            'description': vuln.description[:200] + "..." if len(vuln.description) > 200 else vuln.description,
            'severity': vuln.severity.value,
            'cvss_score': vuln.cvss_base_score,
            'epss_score': vuln.epss_probability,
            'risk_score': vuln.risk_score,
            'published_date': vuln.published_date.isoformat(),
            'last_modified': vuln.last_modified_date.isoformat(),
            'vendors': vuln.affected_vendors[:5],
            'products': vuln.affected_products[:5],
            'cwe_ids': vuln.cwe_ids,
            'kev_status': 'kev' in [tag.lower() for tag in vuln.tags],
            'exploitation_status': vuln.exploitation_status.value,
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
        
        # Build page content
        content_parts = []
        
        # YAML frontmatter
        content_parts.append("---")
        for key, value in frontmatter.items():
            if isinstance(value, str):
                content_parts.append(f'{key}: "{value}"')
            elif isinstance(value, list):
                content_parts.append(f'{key}: {json.dumps(value)}')
            else:
                content_parts.append(f'{key}: {value}')
        content_parts.append("---")
        content_parts.append("")
        
        # Main content
        content_parts.append(f"# {vuln_dict['enhanced_title']}")
        content_parts.append("")
        
        # Overview section
        content_parts.append("## Overview")
        content_parts.append("")
        content_parts.append(f"**CVE ID:** {vuln.cve_id}")
        content_parts.append(f"**Severity:** {vuln.severity.value}")
        content_parts.append(f"**CVSS Score:** {vuln.cvss_base_score or 'N/A'}")
        content_parts.append(f"**EPSS Score:** {vuln.epss_probability or 'N/A'}%")
        content_parts.append(f"**Risk Score:** {vuln.risk_score}/100")
        content_parts.append("")
        content_parts.append("### Description")
        content_parts.append("")
        content_parts.append(vuln.description)
        content_parts.append("")
        
        # Technical Details
        content_parts.append("## Technical Details")
        content_parts.append("")
        
        if vuln.cwe_ids:
            content_parts.append("### Common Weakness Enumeration (CWE)")
            for cwe_id in vuln.cwe_ids:
                content_parts.append(f"- [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html)")
            content_parts.append("")
        
        # CVSS Details
        if vuln.comprehensive_cvss_metrics:
            cvss = vuln.comprehensive_cvss_metrics
            content_parts.append("### CVSS Metrics")
            content_parts.append("")
            content_parts.append(f"**Version:** {cvss['version']}")
            content_parts.append(f"**Vector String:** `{cvss['vectorString']}`")
            content_parts.append(f"**Base Score:** {cvss['baseScore']}")
            content_parts.append(f"**Base Severity:** {cvss['baseSeverity']}")
            
            if cvss.get('attackVector'):
                content_parts.append(f"**Attack Vector:** {cvss['attackVector']['name']}")
            if cvss.get('attackComplexity'):
                content_parts.append(f"**Attack Complexity:** {cvss['attackComplexity']['name']}")
            if cvss.get('privilegesRequired'):
                content_parts.append(f"**Privileges Required:** {cvss['privilegesRequired']['name']}")
            if cvss.get('userInteraction'):
                content_parts.append(f"**User Interaction:** {cvss['userInteraction']['name']}")
            
            content_parts.append("")
        
        # Affected Systems
        if vuln.affected_vendors or vuln.affected_products:
            content_parts.append("### Affected Systems")
            content_parts.append("")
            
            if vuln.affected_vendors:
                content_parts.append("**Vendors:**")
                for vendor in vuln.affected_vendors[:10]:
                    content_parts.append(f"- {vendor}")
                content_parts.append("")
            
            if vuln.affected_products:
                content_parts.append("**Products:**")
                for product in vuln.affected_products[:10]:
                    content_parts.append(f"- {product}")
                content_parts.append("")
        
        # References
        if vuln.references:
            content_parts.append("## References")
            content_parts.append("")
            for ref in vuln.references:
                if ref.tags:
                    content_parts.append(f"- [{ref.url}]({ref.url}) ({', '.join(ref.tags)})")
                else:
                    content_parts.append(f"- [{ref.url}]({ref.url})")
            content_parts.append("")
        
        # Timeline
        content_parts.append("## Timeline")
        content_parts.append("")
        content_parts.append(f"- **Published:** {vuln.published_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        content_parts.append(f"- **Last Modified:** {vuln.last_modified_date.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        content_parts.append("")
        
        # Metadata
        content_parts.append("## Metadata")
        content_parts.append("")
        content_parts.append(f"- **Exploitation Status:** {vuln.exploitation_status.value}")
        
        if 'kev' in [tag.lower() for tag in vuln.tags]:
            content_parts.append("- **⚠️ CISA Known Exploited Vulnerability (KEV)**")
        
        if vuln.tags:
            content_parts.append(f"- **Tags:** {', '.join(vuln.tags[:10])}")
        
        content_parts.append("")
        content_parts.append("---")
        content_parts.append("")
        content_parts.append(f"*Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*")
        
        return "\n".join(content_parts)
    
    async def _generate_index_page(self, vulnerabilities: List, output_dir: Path, config: Dict[str, Any]) -> None:
        """Generate index page for all CVEs.
        
        Args:
            vulnerabilities: List of vulnerability objects
            output_dir: Output directory path
            config: Generation configuration
        """
        index_path = output_dir / "index.md"
        
        # Sort by risk score descending
        sorted_vulns = sorted(vulnerabilities, key=lambda v: v.risk_score, reverse=True)
        
        content_parts = []
        
        # YAML frontmatter
        content_parts.append("---")
        content_parts.append('layout: "cve-index"')
        content_parts.append('title: "CVE Database"')
        content_parts.append(f'description: "Index of {len(vulnerabilities)} vulnerability records"')
        content_parts.append(f'generated_at: "{datetime.now(timezone.utc).isoformat()}"')
        content_parts.append(f'vulnerability_count: {len(vulnerabilities)}')
        content_parts.append("---")
        content_parts.append("")
        
        # Main content
        content_parts.append(f"# CVE Database ({len(vulnerabilities)} vulnerabilities)")
        content_parts.append("")
        content_parts.append("This page contains detailed information about high-risk vulnerabilities.")
        content_parts.append("")
        
        # Statistics
        from collections import Counter
        severity_dist = Counter(v.severity.value for v in vulnerabilities)
        
        content_parts.append("## Statistics")
        content_parts.append("")
        for severity, count in severity_dist.most_common():
            content_parts.append(f"- **{severity}:** {count}")
        content_parts.append("")
        
        # CVE List
        content_parts.append("## Vulnerabilities")
        content_parts.append("")
        
        for vuln in sorted_vulns[:100]:  # Limit to top 100
            enhanced_title = vuln._create_enhanced_title()
            content_parts.append(
                f"- [{enhanced_title}]({vuln.cve_id}.html) "
                f"(Risk: {vuln.risk_score}/100, CVSS: {vuln.cvss_base_score or 'N/A'})"
            )
        
        if len(vulnerabilities) > 100:
            content_parts.append(f"\n*... and {len(vulnerabilities) - 100} more vulnerabilities*")
        
        content_parts.append("")
        content_parts.append("---")
        content_parts.append(f"*Updated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*")
        
        index_content = "\n".join(content_parts)
        index_path.write_text(index_content)
        
        self.logger.info("Generated CVE index page", path=str(index_path), vulnerability_count=len(vulnerabilities))
    
    def get_dependencies(self) -> Set[str]:
        """Get dependencies for change detection."""
        return {
            '.cache/vulns.db',
            'src/_layouts/cve-detail.njk',
            'src/_layouts/cve-index.njk',
            'scripts/processing/cache_manager.py',
            'scripts/models.py'
        }