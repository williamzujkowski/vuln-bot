"""Generate daily vulnerability briefings and JSON API files."""

import json
from pathlib import Path
from typing import Any, Dict, Optional

import structlog

from scripts.models import Vulnerability, VulnerabilityBatch
from scripts.processing.risk_scorer import RiskScorer


class BriefingGenerator:
    """Generate vulnerability briefings in various formats."""

    def __init__(self, output_dir: Path, template_dir: Optional[Path] = None):
        """Initialize briefing generator.

        Args:
            output_dir: Output directory for generated files
            template_dir: Directory containing Jinja2 templates
        """
        self.output_dir = output_dir
        self.template_dir = (
            template_dir or Path(__file__).parent.parent.parent / "templates"
        )
        self.logger = structlog.get_logger(self.__class__.__name__)

        # Create output directories
        self.posts_dir = output_dir / "_posts"
        self.api_dir = output_dir / "api" / "vulns"
        self.posts_dir.mkdir(parents=True, exist_ok=True)
        self.api_dir.mkdir(parents=True, exist_ok=True)

        # Initialize risk scorer for getting risk factors
        self.risk_scorer = RiskScorer()

    def generate_briefing_post(
        self,
        batch: VulnerabilityBatch,
        limit: int = 50,
    ) -> Path:
        """Generate a markdown briefing post.

        Args:
            batch: Vulnerability batch to generate briefing from
            limit: Maximum number of vulnerabilities to include

        Returns:
            Path to generated briefing file
        """
        # Get date for filename
        date_str = batch.generated_at.strftime("%Y-%m-%d")
        filename = f"{date_str}-vuln-brief.md"
        filepath = self.posts_dir / filename

        # Select top vulnerabilities
        top_vulns = batch.sort_by_risk()[:limit]

        # Prepare data for template
        briefing_data = {
            "date": batch.generated_at,
            "date_str": date_str,
            "total_count": batch.count,
            "included_count": len(top_vulns),
            "sources": batch.metadata.get("sources", []),
            "vulnerabilities": [],
            "risk_distribution": {
                "critical": len(
                    [v for v in batch.vulnerabilities if v.risk_score >= 90]
                ),
                "high": len(
                    [v for v in batch.vulnerabilities if 70 <= v.risk_score < 90]
                ),
                "medium": len(
                    [v for v in batch.vulnerabilities if 40 <= v.risk_score < 70]
                ),
                "low": len([v for v in batch.vulnerabilities if v.risk_score < 40]),
            },
            "severity_distribution": {
                "CRITICAL": len(
                    [v for v in batch.vulnerabilities if v.severity.value == "CRITICAL"]
                ),
                "HIGH": len(
                    [v for v in batch.vulnerabilities if v.severity.value == "HIGH"]
                ),
                "MEDIUM": len(
                    [v for v in batch.vulnerabilities if v.severity.value == "MEDIUM"]
                ),
                "LOW": len(
                    [v for v in batch.vulnerabilities if v.severity.value == "LOW"]
                ),
            },
        }

        # Process each vulnerability
        for vuln in top_vulns:
            risk_factors = self.risk_scorer.get_risk_factors(vuln)

            vuln_data = {
                "cve_id": vuln.cve_id,
                "title": vuln.title,
                "description": vuln.description[:500] + "..."
                if len(vuln.description) > 500
                else vuln.description,
                "risk_score": vuln.risk_score,
                "severity": vuln.severity.value,
                "cvss_score": vuln.cvss_base_score,
                "epss_score": vuln.epss_probability,
                "published_date": vuln.published_date.strftime("%Y-%m-%d"),
                "vendors": vuln.affected_vendors[:5],  # Top 5 vendors
                "products": vuln.affected_products[:5],  # Top 5 products
                "tags": vuln.tags,
                "risk_factors": list(risk_factors.values()),
                "references": [
                    ref.url for ref in vuln.references[:3]
                ],  # Top 3 references
            }
            briefing_data["vulnerabilities"].append(vuln_data)

        # Generate markdown content
        content = self._generate_markdown_briefing(briefing_data)

        # Write to file
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

        self.logger.info(
            "Generated briefing post",
            filepath=str(filepath),
            vulnerabilities=len(top_vulns),
        )

        return filepath

    def _generate_markdown_briefing(self, data: Dict[str, Any]) -> str:
        """Generate markdown content for briefing.

        Args:
            data: Briefing data

        Returns:
            Markdown content
        """
        lines = []

        # Front matter
        lines.extend(
            [
                "---",
                f"title: Morning Vulnerability Briefing - {data['date_str']}",
                f"date: {data['date'].isoformat()}",
                "layout: layouts/post.njk",
                "tags: [vulnerability, briefing, security]",
                f"vulnerabilityCount: {data['total_count']}",
                f"criticalCount: {data['risk_distribution']['critical']}",
                f"highCount: {data['risk_distribution']['high']}",
                "---",
                "",
            ]
        )

        # Summary
        lines.extend(
            [
                f"# Morning Vulnerability Briefing - {data['date_str']}",
                "",
                f"Today's briefing covers **{data['total_count']} vulnerabilities** from {len(data['sources'])} sources.",
                "",
                "## Risk Distribution",
                "",
                f"- 🔴 **Critical Risk**: {data['risk_distribution']['critical']} vulnerabilities",
                f"- 🟠 **High Risk**: {data['risk_distribution']['high']} vulnerabilities",
                f"- 🟡 **Medium Risk**: {data['risk_distribution']['medium']} vulnerabilities",
                f"- 🟢 **Low Risk**: {data['risk_distribution']['low']} vulnerabilities",
                "",
                "## Top Vulnerabilities",
                "",
            ]
        )

        # Vulnerability details
        for i, vuln in enumerate(data["vulnerabilities"], 1):
            lines.extend(
                [
                    f"### {i}. [{vuln['cve_id']}](/api/vulns/{vuln['cve_id']}.json)",
                    "",
                    f"**Risk Score**: {vuln['risk_score']}/100 | ",
                    f"**Severity**: {vuln['severity']} | ",
                    f"**CVSS**: {vuln['cvss_score'] or 'N/A'} | ",
                    f"**EPSS**: {vuln['epss_score'] or 0:.1f}%",
                    "",
                    f"**Summary**: {vuln['description']}",
                    "",
                ]
            )

            if vuln["risk_factors"]:
                lines.extend(
                    [
                        "**Risk Factors**:",
                        "",
                    ]
                )
                for factor in vuln["risk_factors"]:
                    lines.append(f"- {factor}")
                lines.append("")

            if vuln["vendors"]:
                lines.append(f"**Affected Vendors**: {', '.join(vuln['vendors'])}")
                lines.append("")

            if vuln["tags"]:
                lines.append(
                    f"**Tags**: {', '.join(f'`{tag}`' for tag in vuln['tags'])}"
                )
                lines.append("")

            if vuln["references"]:
                lines.extend(
                    [
                        "**References**:",
                        "",
                    ]
                )
                for ref in vuln["references"]:
                    lines.append(f"- [{ref}]({ref})")
                lines.append("")

            lines.append("---")
            lines.append("")

        # Footer
        lines.extend(
            [
                "## Data Sources",
                "",
                "This briefing was generated from the following sources:",
                "",
            ]
        )

        for source in data["sources"]:
            status = "✅" if source["status"] == "success" else "❌"
            lines.append(
                f"- {status} {source['name']}: {source['count']} vulnerabilities"
            )

        lines.extend(
            [
                "",
                "---",
                "",
                "*This briefing was automatically generated. For the complete dataset, visit the [vulnerability dashboard](/).*",
            ]
        )

        return "\n".join(lines)

    def generate_vulnerability_json(self, vulnerability: Vulnerability) -> Path:
        """Generate JSON API file for a vulnerability.

        Args:
            vulnerability: Vulnerability to generate JSON for

        Returns:
            Path to generated JSON file
        """
        filename = f"{vulnerability.cve_id}.json"
        filepath = self.api_dir / filename

        # Convert to detailed dictionary
        data = vulnerability.to_detail_dict()

        # Write JSON file
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return filepath

    def generate_search_index(self, batch: VulnerabilityBatch) -> Path:
        """Generate search index JSON file.

        Args:
            batch: Vulnerability batch to index

        Returns:
            Path to generated index file
        """
        filepath = self.api_dir / "index.json"

        # Create index data
        index_data = {
            "generated": batch.generated_at.isoformat(),
            "count": batch.count,
            "vulnerabilities": [
                vuln.to_summary_dict() for vuln in batch.vulnerabilities
            ],
        }

        # Write JSON file
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(index_data, f, indent=2, ensure_ascii=False)

        self.logger.info(
            "Generated search index",
            filepath=str(filepath),
            count=batch.count,
        )

        return filepath

    def generate_all(
        self,
        batch: VulnerabilityBatch,
        briefing_limit: int = 50,
    ) -> Dict[str, Any]:
        """Generate all output files for a vulnerability batch.

        Args:
            batch: Vulnerability batch to process
            briefing_limit: Maximum vulnerabilities in briefing

        Returns:
            Dictionary with paths to generated files
        """
        self.logger.info("Generating all output files", count=batch.count)

        generated_files = {
            "briefing": None,
            "index": None,
            "vulnerabilities": [],
        }

        # Generate briefing post
        try:
            generated_files["briefing"] = str(
                self.generate_briefing_post(batch, limit=briefing_limit)
            )
        except Exception as e:
            self.logger.error("Failed to generate briefing", error=str(e))

        # Generate search index
        try:
            generated_files["index"] = str(self.generate_search_index(batch))
        except Exception as e:
            self.logger.error("Failed to generate index", error=str(e))

        # Generate individual vulnerability JSONs
        for vuln in batch.vulnerabilities:
            try:
                json_path = self.generate_vulnerability_json(vuln)
                generated_files["vulnerabilities"].append(str(json_path))
            except Exception as e:
                self.logger.error(
                    "Failed to generate vulnerability JSON",
                    cve_id=vuln.cve_id,
                    error=str(e),
                )

        self.logger.info(
            "Generation complete",
            briefing=generated_files["briefing"] is not None,
            index=generated_files["index"] is not None,
            vulnerabilities=len(generated_files["vulnerabilities"]),
        )

        return generated_files
