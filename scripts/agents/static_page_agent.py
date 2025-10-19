"""Static Page Agent - Generates static CVE detail pages using Eleventy."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Make Great Expectations optional
try:
    import great_expectations as ge
    from great_expectations.core import ExpectationSuite

    HAS_GREAT_EXPECTATIONS = True
except (ImportError, ValueError):
    # ValueError can occur from numpy/pandas version conflicts
    HAS_GREAT_EXPECTATIONS = False
    ge = None
    ExpectationSuite = None

from scripts.agents.base_agent import BaseAgent
from scripts.agents.enrichment_agent import DataEnrichmentAgent
from scripts.processing.cache_manager import CacheManager


class StaticPageAgent(BaseAgent):
    """Agent responsible for generating static CVE detail pages."""

    def __init__(self, cache_dir: Path = None):
        super().__init__("static_page", cache_dir)
        self.cache_manager = None
        self.enrichment_agent = DataEnrichmentAgent()

        # Configuration
        self.config = {
            "output_dir": "src/cves",
            "template_format": "md",
            "max_pages_per_run": 500,
            "include_full_details": True,
            "generate_index": True,
            "enable_enrichment": True,
            "validate_schema": True,
        }

    def _create_cve_schema_validator(self) -> Optional[ExpectationSuite]:
        """Create Great Expectations validator for CVE Schema v5.1."""
        if not HAS_GREAT_EXPECTATIONS:
            return None
        suite = ExpectationSuite("cve_schema_v5_1")

        # Define expectations for CVE Schema v5.1
        expectations = [
            {
                "expectation_type": "expect_column_to_exist",
                "kwargs": {"column": "cve_id"},
            },
            {
                "expectation_type": "expect_column_values_to_match_regex",
                "kwargs": {"column": "cve_id", "regex": r"^CVE-\d{4}-\d{4,}$"},
            },
            {
                "expectation_type": "expect_column_to_exist",
                "kwargs": {"column": "state"},
            },
            {
                "expectation_type": "expect_column_values_to_be_in_set",
                "kwargs": {
                    "column": "state",
                    "value_set": ["PUBLISHED", "REJECTED", "RESERVED"],
                },
            },
            {
                "expectation_type": "expect_column_to_exist",
                "kwargs": {"column": "assignerOrgId"},
            },
            {
                "expectation_type": "expect_column_to_exist",
                "kwargs": {"column": "description"},
            },
            {
                "expectation_type": "expect_column_to_exist",
                "kwargs": {"column": "problemTypes"},
            },
            {
                "expectation_type": "expect_column_to_exist",
                "kwargs": {"column": "affected"},
            },
            {
                "expectation_type": "expect_column_to_exist",
                "kwargs": {"column": "references"},
            },
        ]

        for exp in expectations:
            suite.add_expectation(exp)

        return suite

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
        output_dir = Path(config["output_dir"])

        results = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "config": config,
            "pages_generated": 0,
            "pages_updated": 0,
            "pages_skipped": 0,
            "enriched_count": 0,
            "validation_failures": 0,
            "success": True,
            "errors": [],
        }

        try:
            # Ensure output directory exists
            output_dir.mkdir(parents=True, exist_ok=True)

            # Get recent vulnerabilities from cache
            vulnerabilities = await asyncio.to_thread(
                self.cache_manager.get_recent_vulnerabilities,
                limit=config["max_pages_per_run"],
            )

            self.logger.info(
                "Generating static pages",
                vulnerability_count=len(vulnerabilities),
                output_dir=str(output_dir),
                enrichment_enabled=config["enable_enrichment"],
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
                            if (
                                f"last_modified: {vuln.last_modified_date.isoformat()}"
                                in existing_content
                            ):
                                should_update = False
                                results["pages_skipped"] += 1
                        except Exception:
                            pass  # If we can't read, regenerate

                    if should_update:
                        # Convert vuln object to dict for enrichment
                        vuln_dict = vuln.to_detail_dict()

                        # Enrich data if enabled
                        if config["enable_enrichment"]:
                            try:
                                enriched_data = (
                                    await self.enrichment_agent.enrich_cve_data(
                                        vuln_dict
                                    )
                                )
                                vuln_dict = enriched_data
                                results["enriched_count"] += 1
                            except Exception as e:
                                self.logger.warning(
                                    f"Enrichment failed for {vuln.cve_id}: {str(e)}"
                                )

                        # Validate schema if enabled
                        if config["validate_schema"]:
                            validation_passed = self._validate_cve_schema(vuln_dict)
                            if not validation_passed:
                                results["validation_failures"] += 1

                        # Generate page content
                        page_content = await self._generate_page_content_enhanced(
                            vuln, vuln_dict
                        )

                        # Write page
                        page_path.write_text(page_content)

                        if page_path in existing_files:
                            results["pages_updated"] += 1
                        else:
                            results["pages_generated"] += 1

                        self.logger.debug(
                            "Generated page", cve_id=vuln.cve_id, path=str(page_path)
                        )

                except Exception as e:
                    error_msg = f"Failed to generate page for {vuln.cve_id}: {str(e)}"
                    results["errors"].append(error_msg)
                    self.logger.error(error_msg)

            # Clean up obsolete files
            obsolete_files = existing_files - current_files
            for obsolete_file in obsolete_files:
                try:
                    obsolete_file.unlink()
                    self.logger.debug("Removed obsolete page", path=str(obsolete_file))
                except Exception as e:
                    self.logger.warning(
                        "Failed to remove obsolete page",
                        path=str(obsolete_file),
                        error=str(e),
                    )

            # Generate index page if requested
            if config.get("generate_index"):
                await self._generate_index_page(vulnerabilities, output_dir)

            results["obsolete_files_removed"] = len(obsolete_files)
            results["completed_at"] = datetime.now(timezone.utc).isoformat()

            self.logger.info(
                "Static page generation completed",
                pages_generated=results["pages_generated"],
                pages_updated=results["pages_updated"],
                pages_skipped=results["pages_skipped"],
                obsolete_removed=results["obsolete_files_removed"],
            )

            return results

        except Exception as e:
            results["success"] = False
            results["errors"].append(str(e))
            results["completed_at"] = datetime.now(timezone.utc).isoformat()

            self.logger.error("Static page generation failed", error=str(e))
            raise

    def _validate_cve_schema(self, vuln_dict: Dict[str, Any]) -> bool:
        """Validate CVE data against schema v5.1."""
        try:
            # Check required fields
            required_fields = ["cve_id", "description", "severity"]
            for field in required_fields:
                if field not in vuln_dict or not vuln_dict[field]:
                    self.logger.warning(f"Missing required field: {field}")
                    return False

            # Validate CVE ID format
            import re

            if not re.match(r"^CVE-\d{4}-\d{4,}$", vuln_dict["cve_id"]):
                self.logger.warning(f"Invalid CVE ID format: {vuln_dict['cve_id']}")
                return False

            return True
        except Exception as e:
            self.logger.error(f"Schema validation error: {str(e)}")
            return False

    async def _generate_page_content_enhanced(
        self, vuln, vuln_dict: Dict[str, Any]
    ) -> str:
        """Generate enhanced content for a single CVE page with all schema v5.1 fields.

        Args:
            vuln: Vulnerability object
            vuln_dict: Enriched vulnerability dictionary

        Returns:
            Page content as string
        """
        # Extract comprehensive data
        enhanced_title = vuln._create_enhanced_title()

        # Extract metadata from enrichment or use defaults
        metadata = {
            "assignerOrgId": vuln_dict.get("assignerOrgId", "Unknown"),
            "state": vuln_dict.get("state", "PUBLISHED"),
            "dateReserved": vuln_dict.get("dateReserved"),
            "datePublished": vuln.published_date.isoformat(),
            "dateUpdated": vuln.last_modified_date.isoformat(),
        }

        # Extract enrichment data
        enrichment = vuln_dict.get("enrichment", {})
        deps_dev_data = enrichment.get("deps_dev", {})
        problem_types = enrichment.get("problem_types", [])
        structured_affected = enrichment.get("structured_affected", [])
        all_references = enrichment.get("all_references", [])

        # YAML frontmatter
        frontmatter = {
            "layout": "cve-detail",
            "cve_id": vuln.cve_id,
            "title": enhanced_title,
            "description": (
                vuln.description[:200] + "..."
                if len(vuln.description) > 200
                else vuln.description
            ),
            "severity": vuln.severity.value,
            "cvss_score": vuln.cvss_base_score,
            "epss_score": vuln.epss_probability,
            "risk_score": vuln.risk_score,
            "published_date": vuln.published_date.isoformat(),
            "last_modified": vuln.last_modified_date.isoformat(),
            "vendors": vuln.affected_vendors[:5],
            "products": vuln.affected_products[:5],
            "cwe_ids": [tag for tag in vuln.tags if tag.startswith("CWE-")],
            "kev_status": "kev" in [tag.lower() for tag in vuln.tags],
            "exploitation_status": vuln.exploitation_status.value,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "state": metadata["state"],
            "assignerOrgId": metadata["assignerOrgId"],
            "has_deps_data": bool(deps_dev_data),
            "total_affected_packages": deps_dev_data.get("total_affected", 0),
        }

        # Build page content
        content_parts = []

        # YAML frontmatter
        content_parts.append("---")
        for key, value in frontmatter.items():
            if isinstance(value, str):
                content_parts.append(f'{key}: "{value}"')
            elif isinstance(value, list):
                content_parts.append(f"{key}: {json.dumps(value)}")
            else:
                content_parts.append(f"{key}: {value}")
        content_parts.append("---")
        content_parts.append("")

        # Main content
        content_parts.append(f"# {enhanced_title}")
        content_parts.append("")

        # Metadata section
        content_parts.append("## Metadata")
        content_parts.append("")
        content_parts.append(f"**CVE ID:** {vuln.cve_id}")
        content_parts.append(f"**State:** {metadata['state']}")
        content_parts.append(
            f"**Assigner Organization ID:** {metadata['assignerOrgId']}"
        )
        if metadata.get("dateReserved"):
            content_parts.append(f"**Date Reserved:** {metadata['dateReserved']}")
        content_parts.append(f"**Date Published:** {metadata['datePublished']}")
        content_parts.append(f"**Date Updated:** {metadata['dateUpdated']}")
        content_parts.append("")

        # Overview section
        content_parts.append("## Overview")
        content_parts.append("")
        content_parts.append(f"**Severity:** {vuln.severity.value}")
        content_parts.append(f"**CVSS Score:** {vuln.cvss_base_score or 'N/A'}")
        content_parts.append(f"**EPSS Score:** {vuln.epss_probability or 'N/A'}%")
        content_parts.append(f"**Risk Score:** {vuln.risk_score}/100")
        content_parts.append("")

        # Description with multiline support
        content_parts.append("### Description")
        content_parts.append("")
        # Handle multiline descriptions properly
        description_lines = vuln.description.split("\n")
        for line in description_lines:
            content_parts.append(line)
        content_parts.append("")

        # Problem Types / CWEs
        cwe_ids_from_tags = [tag for tag in vuln.tags if tag.startswith("CWE-")]
        if problem_types or cwe_ids_from_tags:
            content_parts.append("## Problem Types")
            content_parts.append("")

            # From enrichment
            if problem_types:
                for pt in problem_types:
                    cwe_id = pt.get("id", "")
                    desc = pt.get("description", "")
                    if cwe_id:
                        content_parts.append(
                            f"- **{cwe_id}**: {desc} "
                            f"([Details](https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html))"
                        )
            # Fallback to original CWE IDs
            elif cwe_ids_from_tags:
                for cwe_id in cwe_ids_from_tags:
                    content_parts.append(
                        f"- [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html)"
                    )
            content_parts.append("")

        # Technical Details
        content_parts.append("## Technical Details")
        content_parts.append("")

        # CVSS Details
        if vuln.cvss_metrics:
            # Get the highest scored CVSS metric
            cvss_metric = max(vuln.cvss_metrics, key=lambda m: m.base_score)
            content_parts.append("### CVSS Metrics")
            content_parts.append("")
            content_parts.append(f"**Version:** {cvss_metric.version}")
            content_parts.append(f"**Vector String:** `{cvss_metric.vector_string}`")
            content_parts.append(f"**Base Score:** {cvss_metric.base_score}")
            content_parts.append(
                f"**Base Severity:** {cvss_metric.base_severity.value}"
            )

            # Extract CVSS components from vector string if available
            if hasattr(vuln, "attack_vector") and vuln.attack_vector:
                content_parts.append("")
                content_parts.append("#### Attack Vector Details")
                content_parts.append(f"- **Attack Vector:** {vuln.attack_vector}")
                if hasattr(vuln, "attack_complexity") and vuln.attack_complexity:
                    content_parts.append(
                        f"- **Attack Complexity:** {vuln.attack_complexity}"
                    )
                if hasattr(vuln, "privileges_required") and vuln.privileges_required:
                    content_parts.append(
                        f"- **Privileges Required:** {vuln.privileges_required}"
                    )
                if hasattr(vuln, "user_interaction") and vuln.user_interaction:
                    content_parts.append(
                        f"- **User Interaction:** {vuln.user_interaction}"
                    )

            content_parts.append("")

        # Affected Systems (structured)
        content_parts.append("### Affected Products")
        content_parts.append("")

        if structured_affected:
            for affected in structured_affected:
                vendor = affected.get("vendor", "Unknown")
                product = affected.get("product", "Unknown")
                content_parts.append(f"#### {vendor} - {product}")

                versions = affected.get("versions", [])
                if versions:
                    content_parts.append("**Affected Versions:**")
                    for ver in versions:
                        version = ver.get("version", "Unknown")
                        status = ver.get("status", "affected")
                        content_parts.append(f"- {version} ({status})")

                platforms = affected.get("platforms", [])
                if platforms:
                    content_parts.append(f"**Platforms:** {', '.join(platforms)}")

                content_parts.append("")
        else:
            # Fallback to simple lists
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

        # CPE Matches
        if vuln_dict.get("cpe_matches"):
            content_parts.append("### CPE Matches")
            content_parts.append("")
            for cpe in vuln_dict["cpe_matches"][:10]:
                content_parts.append(f"- `{cpe}`")
            content_parts.append("")

        # Impacted Projects from deps.dev (using enhanced format)
        package_impact = enrichment.get("package_impact", [])
        if package_impact:
            content_parts.append("## Impacted Open Source Projects")
            content_parts.append("")

            # Summary with patch availability
            impact_summary = enrichment.get("impact_summary", {})
            patch_info = impact_summary.get("patch_availability", {})

            content_parts.append(
                f"*This vulnerability affects **{impact_summary.get('total_affected_packages', 0)}** packages "
                f"across **{len(impact_summary.get('affected_ecosystems', []))}** ecosystems.*"
            )

            if patch_info.get("percentage", 0) > 0:
                content_parts.append(
                    f"*Patches available for **{patch_info['patched']}/{patch_info['total']}** "
                    f"({patch_info['percentage']}%) of affected packages.*"
                )
            content_parts.append("")

            # Group packages by ecosystem for display
            packages_by_ecosystem = {}
            for pkg in package_impact:
                ecosystem = pkg.get("ecosystem", "Unknown")
                if ecosystem not in packages_by_ecosystem:
                    packages_by_ecosystem[ecosystem] = []
                packages_by_ecosystem[ecosystem].append(pkg)

            # Display by ecosystem
            for ecosystem, packages in sorted(packages_by_ecosystem.items()):
                content_parts.append(f"### {ecosystem.upper()}")
                content_parts.append("")

                # Create a table for better formatting
                content_parts.append(
                    "| Package | Version Range | Severity | Patch Available |"
                )
                content_parts.append(
                    "|---------|---------------|----------|-----------------|"
                )

                for pkg in packages[:10]:  # Show top 10 per ecosystem
                    name = pkg.get("name", "Unknown")
                    version_range = pkg.get("version_range", "Unknown")
                    severity = pkg.get("severity", "UNKNOWN")
                    patch_available = "✅" if pkg.get("patch_available") else "❌"

                    # Add latest safe version if available
                    if pkg.get("latest_safe_version"):
                        patch_available += f" ({pkg['latest_safe_version']})"

                    content_parts.append(
                        f"| {name} | {version_range} | {severity} | {patch_available} |"
                    )

                if len(packages) > 10:
                    content_parts.append(
                        f"\n*... and {len(packages) - 10} more {ecosystem} packages*"
                    )
                content_parts.append("")

        # Exploitation Intelligence Section
        exploitation_intel = enrichment.get("exploitation_intel", {})
        if exploitation_intel:
            content_parts.append("## Exploitation Intelligence")
            content_parts.append("")

            risk_level = exploitation_intel.get("risk_level", "UNKNOWN")
            risk_emoji = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡",
                "LOW": "🟢",
                "UNKNOWN": "⚪",
            }.get(risk_level, "⚪")

            content_parts.append(f"**Risk Level:** {risk_emoji} {risk_level}")
            content_parts.append("")

            risk_factors = exploitation_intel.get("risk_factors", [])
            if risk_factors:
                content_parts.append("**Risk Factors:**")
                for factor in risk_factors:
                    content_parts.append(f"- {factor}")
                content_parts.append("")

            recommendation = exploitation_intel.get("recommendation", "")
            if recommendation:
                content_parts.append(f"**Recommendation:** {recommendation}")
                content_parts.append("")

        # References (using enhanced categorized format)
        categorized_refs = enrichment.get("categorized_references", {})
        if categorized_refs:
            content_parts.append("## References")
            content_parts.append("")

            # Display references by category with better naming
            category_display = {
                "vendor_advisories": "### Vendor Advisories",
                "patches": "### Patches",
                "exploits": "### 🚨 Exploits",
                "technical_details": "### Technical Details",
                "media_coverage": "### Media Coverage",
                "other": "### Other References",
            }

            for category, refs in categorized_refs.items():
                if refs:
                    content_parts.append(
                        category_display.get(
                            category, f"### {category.replace('_', ' ').title()}"
                        )
                    )
                    for ref in refs[:10]:  # Limit to 10 per category
                        url = ref.get("url", "")
                        source = ref.get("source", "")
                        content_parts.append(f"- [{url}]({url}) (from {source})")

                    if len(refs) > 10:
                        content_parts.append(
                            f"*... and {len(refs) - 10} more {category.replace('_', ' ')}*"
                        )
                    content_parts.append("")
        elif all_references:
            # Fallback to simple reference list
            content_parts.append("## References")
            content_parts.append("")

            # Group references by tag
            refs_by_tag = {}
            for ref in all_references:
                tags = ref.get("tags", ["Other"])
                for tag in tags:
                    if tag not in refs_by_tag:
                        refs_by_tag[tag] = []
                    refs_by_tag[tag].append(ref)

            # Display references by category
            tag_order = [
                "CVE Record",
                "Vendor Advisory",
                "Patch",
                "Exploit",
                "Issue Tracking",
                "Third Party Advisory",
                "Media Coverage",
                "Other",
            ]

            for tag in tag_order:
                if tag in refs_by_tag:
                    content_parts.append(f"### {tag}")
                    for ref in refs_by_tag[tag][:10]:  # Limit refs per category
                        url = ref.get("url", "")
                        source = ref.get("source", "")
                        if source:
                            content_parts.append(f"- [{url}]({url}) (from {source})")
                        else:
                            content_parts.append(f"- [{url}]({url})")
                    content_parts.append("")
        elif vuln.references:
            # Fallback to original references
            content_parts.append("## References")
            content_parts.append("")
            for ref in vuln.references:
                if ref.tags:
                    content_parts.append(
                        f"- [{ref.url}]({ref.url}) ({', '.join(ref.tags)})"
                    )
                else:
                    content_parts.append(f"- [{ref.url}]({ref.url})")
            content_parts.append("")

        # Credits / Acknowledgments
        if vuln_dict.get("credits"):
            content_parts.append("## Credits")
            content_parts.append("")
            for credit in vuln_dict["credits"]:
                content_parts.append(f"- {credit}")
            content_parts.append("")

        # Timeline
        content_parts.append("## Timeline")
        content_parts.append("")
        if metadata.get("dateReserved"):
            content_parts.append(f"- **Reserved:** {metadata['dateReserved']}")
        content_parts.append(
            f"- **Published:** {vuln.published_date.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        content_parts.append(
            f"- **Last Modified:** {vuln.last_modified_date.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        if "kev" in [tag.lower() for tag in vuln.tags]:
            content_parts.append("- **Added to KEV:** Yes")
        content_parts.append("")

        # Additional Metadata
        content_parts.append("## Additional Information")
        content_parts.append("")
        content_parts.append(
            f"- **Exploitation Status:** {vuln.exploitation_status.value}"
        )

        if vuln.tags:
            content_parts.append(f"- **Tags:** {', '.join(vuln.tags[:20])}")

        if enrichment.get("sources"):
            content_parts.append(
                f"- **Data Sources:** {', '.join(enrichment['sources'])}"
            )

        content_parts.append("")
        content_parts.append("---")
        content_parts.append("")
        content_parts.append(
            f"*Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} "
            f"with enrichment from deps.dev API*"
        )

        return "\n".join(content_parts)

    async def _generate_page_content(self, vuln) -> str:
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
        vuln_dict["enhanced_title"] = vuln._create_enhanced_title()
        vuln_dict["cwe_ids"] = [tag for tag in vuln.tags if tag.startswith("CWE-")]
        # Extract CVSS data properly
        if vuln.cvss_metrics:
            cvss_metric = max(vuln.cvss_metrics, key=lambda m: m.base_score)
            vuln_dict["comprehensive_cvss"] = {
                "version": cvss_metric.version,
                "vectorString": cvss_metric.vector_string,
                "baseScore": cvss_metric.base_score,
                "baseSeverity": cvss_metric.base_severity.value,
            }
        else:
            vuln_dict["comprehensive_cvss"] = None

        # YAML frontmatter
        frontmatter = {
            "layout": "cve-detail",
            "cve_id": vuln.cve_id,
            "title": vuln_dict["enhanced_title"],
            "description": (
                vuln.description[:200] + "..."
                if len(vuln.description) > 200
                else vuln.description
            ),
            "severity": vuln.severity.value,
            "cvss_score": vuln.cvss_base_score,
            "epss_score": vuln.epss_probability,
            "risk_score": vuln.risk_score,
            "published_date": vuln.published_date.isoformat(),
            "last_modified": vuln.last_modified_date.isoformat(),
            "vendors": vuln.affected_vendors[:5],
            "products": vuln.affected_products[:5],
            "cwe_ids": [tag for tag in vuln.tags if tag.startswith("CWE-")],
            "kev_status": "kev" in [tag.lower() for tag in vuln.tags],
            "exploitation_status": vuln.exploitation_status.value,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # Build page content
        content_parts = []

        # YAML frontmatter
        content_parts.append("---")
        for key, value in frontmatter.items():
            if isinstance(value, str):
                content_parts.append(f'{key}: "{value}"')
            elif isinstance(value, list):
                content_parts.append(f"{key}: {json.dumps(value)}")
            else:
                content_parts.append(f"{key}: {value}")
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

        cwe_ids_from_tags = [tag for tag in vuln.tags if tag.startswith("CWE-")]
        if cwe_ids_from_tags:
            content_parts.append("### Common Weakness Enumeration (CWE)")
            for cwe_id in cwe_ids_from_tags:
                content_parts.append(
                    f"- [{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html)"
                )
            content_parts.append("")

        # CVSS Details
        if vuln.cvss_metrics:
            # Get the highest scored CVSS metric
            cvss_metric = max(vuln.cvss_metrics, key=lambda m: m.base_score)
            cvss = {
                "version": cvss_metric.version,
                "vectorString": cvss_metric.vector_string,
                "baseScore": cvss_metric.base_score,
                "baseSeverity": cvss_metric.base_severity.value,
            }
            content_parts.append("### CVSS Metrics")
            content_parts.append("")
            content_parts.append(f"**Version:** {cvss['version']}")
            content_parts.append(f"**Vector String:** `{cvss['vectorString']}`")
            content_parts.append(f"**Base Score:** {cvss['baseScore']}")
            content_parts.append(f"**Base Severity:** {cvss['baseSeverity']}")

            if cvss.get("attackVector"):
                content_parts.append(
                    f"**Attack Vector:** {cvss['attackVector']['name']}"
                )
            if cvss.get("attackComplexity"):
                content_parts.append(
                    f"**Attack Complexity:** {cvss['attackComplexity']['name']}"
                )
            if cvss.get("privilegesRequired"):
                content_parts.append(
                    f"**Privileges Required:** {cvss['privilegesRequired']['name']}"
                )
            if cvss.get("userInteraction"):
                content_parts.append(
                    f"**User Interaction:** {cvss['userInteraction']['name']}"
                )

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
                    content_parts.append(
                        f"- [{ref.url}]({ref.url}) ({', '.join(ref.tags)})"
                    )
                else:
                    content_parts.append(f"- [{ref.url}]({ref.url})")
            content_parts.append("")

        # Timeline
        content_parts.append("## Timeline")
        content_parts.append("")
        content_parts.append(
            f"- **Published:** {vuln.published_date.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        content_parts.append(
            f"- **Last Modified:** {vuln.last_modified_date.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        content_parts.append("")

        # Metadata
        content_parts.append("## Metadata")
        content_parts.append("")
        content_parts.append(
            f"- **Exploitation Status:** {vuln.exploitation_status.value}"
        )

        if "kev" in [tag.lower() for tag in vuln.tags]:
            content_parts.append("- **⚠️ CISA Known Exploited Vulnerability (KEV)**")

        if vuln.tags:
            content_parts.append(f"- **Tags:** {', '.join(vuln.tags[:10])}")

        content_parts.append("")
        content_parts.append("---")
        content_parts.append("")
        content_parts.append(
            f"*Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*"
        )

        return "\n".join(content_parts)

    async def _generate_index_page(
        self, vulnerabilities: List, output_dir: Path
    ) -> None:
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
        content_parts.append(
            f'description: "Index of {len(vulnerabilities)} vulnerability records"'
        )
        content_parts.append(
            f'generated_at: "{datetime.now(timezone.utc).isoformat()}"'
        )
        content_parts.append(f"vulnerability_count: {len(vulnerabilities)}")
        content_parts.append("---")
        content_parts.append("")

        # Main content
        content_parts.append(f"# CVE Database ({len(vulnerabilities)} vulnerabilities)")
        content_parts.append("")
        content_parts.append(
            "This page contains detailed information about high-risk vulnerabilities."
        )
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
            content_parts.append(
                f"\n*... and {len(vulnerabilities) - 100} more vulnerabilities*"
            )

        content_parts.append("")
        content_parts.append("---")
        content_parts.append(
            f"*Updated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*"
        )

        index_content = "\n".join(content_parts)
        index_path.write_text(index_content)

        self.logger.info(
            "Generated CVE index page",
            path=str(index_path),
            vulnerability_count=len(vulnerabilities),
        )

    def get_dependencies(self) -> Set[str]:
        """Get dependencies for change detection."""
        return {
            ".cache/vulns.db",
            "scripts/processing/cache_manager.py",
            "scripts/models.py",
        }
