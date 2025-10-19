#!/usr/bin/env python3
"""
DataQualityReportAgent - Generates comprehensive data quality reports with EPSS filtering statistics.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.agents.base_agent import BaseAgent


class DataQualityReportAgent(BaseAgent):
    """Agent for generating comprehensive data quality reports."""

    def __init__(
        self, cache_dir: Optional[Path] = None, output_dir: Optional[Path] = None
    ):
        """
        Initialize Data Quality Report Agent.

        Args:
            cache_dir: Directory for caching filtered results
            output_dir: Directory for report output (defaults to reports/)
        """
        super().__init__(name="DataQualityReportAgent", cache_dir=cache_dir)

        self.output_dir = output_dir or Path("reports")
        self.output_dir.mkdir(exist_ok=True)

        self.logger.info(
            "Data Quality Report Agent initialized", output_dir=str(self.output_dir)
        )

    def analyze_epss_distribution(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze EPSS score distribution in vulnerability dataset.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with EPSS distribution analysis
        """
        epss_analysis = {
            "total_vulnerabilities": len(vulnerabilities),
            "with_epss_score": 0,
            "missing_epss_score": 0,
            "epss_statistics": {},
            "distribution_ranges": {},
            "threshold_compliance": {},
        }

        epss_scores = []
        for vuln in vulnerabilities:
            epss_score = self._extract_epss_score(vuln)
            if epss_score is not None:
                epss_scores.append(epss_score)
                epss_analysis["with_epss_score"] += 1
            else:
                epss_analysis["missing_epss_score"] += 1

        if epss_scores:
            # Basic statistics
            epss_analysis["epss_statistics"] = {
                "min": min(epss_scores),
                "max": max(epss_scores),
                "mean": sum(epss_scores) / len(epss_scores),
                "median": sorted(epss_scores)[len(epss_scores) // 2],
                "count": len(epss_scores),
            }

            # Distribution by ranges
            ranges = [
                (0.0, 0.1, "0-10%"),
                (0.1, 0.2, "10-20%"),
                (0.2, 0.3, "20-30%"),
                (0.3, 0.4, "30-40%"),
                (0.4, 0.5, "40-50%"),
                (0.5, 0.6, "50-60%"),
                (0.6, 0.7, "60-70%"),
                (0.7, 0.8, "70-80%"),
                (0.8, 0.9, "80-90%"),
                (0.9, 1.0, "90-100%"),
            ]

            for min_val, max_val, label in ranges:
                count = len(
                    [
                        s
                        for s in epss_scores
                        if min_val <= s < max_val or (max_val == 1.0 and s == 1.0)
                    ]
                )
                percentage = (count / len(epss_scores)) * 100 if epss_scores else 0
                epss_analysis["distribution_ranges"][label] = {
                    "count": count,
                    "percentage": round(percentage, 2),
                }

            # Threshold compliance analysis
            thresholds = [0.5, 0.6, 0.7, 0.8, 0.9]
            for threshold in thresholds:
                above_threshold = len([s for s in epss_scores if s >= threshold])
                compliance_rate = (
                    (above_threshold / len(epss_scores)) * 100 if epss_scores else 0
                )
                epss_analysis["threshold_compliance"][f"{int(threshold * 100)}%"] = {
                    "count": above_threshold,
                    "percentage": round(compliance_rate, 2),
                }

        return epss_analysis

    def analyze_vendor_breakdown(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze vulnerability distribution by vendor.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with vendor analysis
        """
        vendor_analysis = {
            "total_vendors": 0,
            "top_vendors": [],
            "vendor_distribution": {},
            "unknown_vendors": 0,
        }

        vendor_counts = {}
        unknown_count = 0

        for vuln in vulnerabilities:
            vendors = vuln.get("vendors", [])
            if (
                not vendors
                or vendors == []
                or (len(vendors) == 1 and vendors[0].lower() in ["unknown", "n/a", ""])
            ):
                unknown_count += 1
            else:
                for vendor in vendors:
                    if vendor and vendor.lower() not in ["unknown", "n/a", ""]:
                        vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1

        vendor_analysis["total_vendors"] = len(vendor_counts)
        vendor_analysis["unknown_vendors"] = unknown_count

        # Sort vendors by count and get top 10
        sorted_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)
        vendor_analysis["top_vendors"] = [
            {
                "vendor": vendor,
                "count": count,
                "percentage": round((count / len(vulnerabilities)) * 100, 2),
            }
            for vendor, count in sorted_vendors[:10]
        ]

        vendor_analysis["vendor_distribution"] = dict(sorted_vendors)

        return vendor_analysis

    def analyze_severity_distribution(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze vulnerability distribution by severity.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with severity analysis
        """
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["UNKNOWN"] += 1

        total = len(vulnerabilities)
        severity_analysis = {"total_vulnerabilities": total, "distribution": {}}

        for severity, count in severity_counts.items():
            percentage = (count / total) * 100 if total > 0 else 0
            severity_analysis["distribution"][severity] = {
                "count": count,
                "percentage": round(percentage, 2),
            }

        return severity_analysis

    def analyze_cvss_distribution(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze CVSS score distribution.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with CVSS analysis
        """
        cvss_analysis = {
            "total_vulnerabilities": len(vulnerabilities),
            "with_cvss_score": 0,
            "missing_cvss_score": 0,
            "cvss_statistics": {},
            "score_ranges": {},
        }

        cvss_scores = []
        for vuln in vulnerabilities:
            cvss_score = vuln.get("cvssScore") or vuln.get("cvss_base_score")
            if cvss_score is not None and isinstance(cvss_score, (int, float)):
                cvss_scores.append(float(cvss_score))
                cvss_analysis["with_cvss_score"] += 1
            else:
                cvss_analysis["missing_cvss_score"] += 1

        if cvss_scores:
            cvss_analysis["cvss_statistics"] = {
                "min": min(cvss_scores),
                "max": max(cvss_scores),
                "mean": round(sum(cvss_scores) / len(cvss_scores), 2),
                "median": round(sorted(cvss_scores)[len(cvss_scores) // 2], 2),
                "count": len(cvss_scores),
            }

            # CVSS score ranges
            ranges = [
                (0.0, 3.9, "Low (0.0-3.9)"),
                (4.0, 6.9, "Medium (4.0-6.9)"),
                (7.0, 8.9, "High (7.0-8.9)"),
                (9.0, 10.0, "Critical (9.0-10.0)"),
            ]

            for min_val, max_val, label in ranges:
                count = len([s for s in cvss_scores if min_val <= s <= max_val])
                percentage = (count / len(cvss_scores)) * 100 if cvss_scores else 0
                cvss_analysis["score_ranges"][label] = {
                    "count": count,
                    "percentage": round(percentage, 2),
                }

        return cvss_analysis

    def analyze_temporal_trends(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze temporal trends in vulnerability data.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with temporal analysis
        """
        temporal_analysis = {"by_year": {}, "by_month": {}, "date_range": {}}

        dates = []
        for vuln in vulnerabilities:
            published_date = vuln.get("publishedDate")
            if published_date:
                try:
                    if isinstance(published_date, str):
                        # Parse ISO format date
                        date_obj = datetime.fromisoformat(
                            published_date.replace("Z", "+00:00")
                        )
                    else:
                        date_obj = published_date

                    dates.append(date_obj)

                    year = date_obj.year
                    month = f"{date_obj.year}-{date_obj.month:02d}"

                    temporal_analysis["by_year"][str(year)] = (
                        temporal_analysis["by_year"].get(str(year), 0) + 1
                    )
                    temporal_analysis["by_month"][month] = (
                        temporal_analysis["by_month"].get(month, 0) + 1
                    )

                except Exception:
                    continue

        if dates:
            temporal_analysis["date_range"] = {
                "earliest": min(dates).isoformat(),
                "latest": max(dates).isoformat(),
                "span_days": (max(dates) - min(dates)).days,
            }

        return temporal_analysis

    def generate_quality_report(
        self,
        vulnerabilities: List[Dict[str, Any]],
        harvest_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Generate comprehensive data quality report.

        Args:
            vulnerabilities: List of vulnerability dictionaries
            harvest_metadata: Optional metadata from harvest process

        Returns:
            Complete quality report dictionary
        """
        self.logger.info(
            "Generating comprehensive data quality report", count=len(vulnerabilities)
        )

        report = {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "DataQualityReportAgent",
                "version": "1.0.0",
                "total_vulnerabilities": len(vulnerabilities),
            },
            "harvest_metadata": harvest_metadata or {},
            "epss_analysis": self.analyze_epss_distribution(vulnerabilities),
            "vendor_analysis": self.analyze_vendor_breakdown(vulnerabilities),
            "severity_analysis": self.analyze_severity_distribution(vulnerabilities),
            "cvss_analysis": self.analyze_cvss_distribution(vulnerabilities),
            "temporal_analysis": self.analyze_temporal_trends(vulnerabilities),
            "quality_summary": {},
        }

        # Generate quality summary
        epss_analysis = report["epss_analysis"]
        vendor_analysis = report["vendor_analysis"]
        cvss_analysis = report["cvss_analysis"]

        report["quality_summary"] = {
            "data_completeness": {
                "epss_coverage": (
                    round(
                        (
                            epss_analysis["with_epss_score"]
                            / epss_analysis["total_vulnerabilities"]
                        )
                        * 100,
                        2,
                    )
                    if epss_analysis["total_vulnerabilities"] > 0
                    else 0
                ),
                "cvss_coverage": (
                    round(
                        (
                            cvss_analysis["with_cvss_score"]
                            / cvss_analysis["total_vulnerabilities"]
                        )
                        * 100,
                        2,
                    )
                    if cvss_analysis["total_vulnerabilities"] > 0
                    else 0
                ),
                "vendor_identification": (
                    round(
                        (
                            (
                                epss_analysis["total_vulnerabilities"]
                                - vendor_analysis["unknown_vendors"]
                            )
                            / epss_analysis["total_vulnerabilities"]
                        )
                        * 100,
                        2,
                    )
                    if epss_analysis["total_vulnerabilities"] > 0
                    else 0
                ),
            },
            "epss_threshold_compliance": {
                "current_threshold": "60%",
                "compliant_vulnerabilities": epss_analysis["threshold_compliance"]
                .get("60%", {})
                .get("count", 0),
                "compliance_rate": epss_analysis["threshold_compliance"]
                .get("60%", {})
                .get("percentage", 0),
            },
            "risk_distribution": {
                "critical_severity": report["severity_analysis"]["distribution"][
                    "CRITICAL"
                ]["count"],
                "high_severity": report["severity_analysis"]["distribution"]["HIGH"][
                    "count"
                ],
                "high_epss": epss_analysis["threshold_compliance"]
                .get("80%", {})
                .get("count", 0),
            },
        }

        return report

    def save_report_json(
        self, report: Dict[str, Any], filename: Optional[str] = None
    ) -> Path:
        """
        Save report as JSON file.

        Args:
            report: Report dictionary
            filename: Optional custom filename

        Returns:
            Path to saved file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"data_quality_report_{timestamp}.json"

        output_path = self.output_dir / filename

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        self.logger.info("Saved JSON report", path=str(output_path))
        return output_path

    def save_report_html(
        self, report: Dict[str, Any], filename: Optional[str] = None
    ) -> Path:
        """
        Save report as HTML file.

        Args:
            report: Report dictionary
            filename: Optional custom filename

        Returns:
            Path to saved file
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"data_quality_report_{timestamp}.html"

        output_path = self.output_dir / filename

        html_content = self._generate_html_report(report)

        with open(output_path, "w") as f:
            f.write(html_content)

        self.logger.info("Saved HTML report", path=str(output_path))
        return output_path

    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML representation of the report."""
        metadata = report["report_metadata"]
        epss = report["epss_analysis"]
        quality = report["quality_summary"]

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Data Quality Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .section {{ margin-bottom: 30px; }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }}
        .metric-card {{ background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #333; }}
        .metric-label {{ color: #666; font-size: 0.9em; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        .good {{ color: #27ae60; }}
        .warning {{ color: #f39c12; }}
        .critical {{ color: #e74c3c; }}
        .distribution-bar {{ background: #e0e0e0; height: 20px; border-radius: 10px; overflow: hidden; }}
        .distribution-fill {{ height: 100%; background: linear-gradient(90deg, #3498db, #2ecc71); }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Vulnerability Data Quality Report</h1>
        <p><strong>Generated:</strong> {metadata["generated_at"]}</p>
        <p><strong>Total Vulnerabilities:</strong> {metadata["total_vulnerabilities"]:,}</p>
        <p><strong>Generator:</strong> {metadata["generator"]} v{metadata["version"]}</p>
    </div>

    <div class="section">
        <h2>📊 Key Quality Metrics</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value {"good" if quality["data_completeness"]["epss_coverage"] >= 90 else "warning" if quality["data_completeness"]["epss_coverage"] >= 70 else "critical"}">{quality["data_completeness"]["epss_coverage"]:.1f}%</div>
                <div class="metric-label">EPSS Coverage</div>
            </div>
            <div class="metric-card">
                <div class="metric-value {"good" if quality["epss_threshold_compliance"]["compliance_rate"] == 100 else "warning" if quality["epss_threshold_compliance"]["compliance_rate"] >= 80 else "critical"}">{quality["epss_threshold_compliance"]["compliance_rate"]:.1f}%</div>
                <div class="metric-label">EPSS ≥60% Compliance</div>
            </div>
            <div class="metric-card">
                <div class="metric-value {"good" if quality["data_completeness"]["cvss_coverage"] >= 90 else "warning" if quality["data_completeness"]["cvss_coverage"] >= 70 else "critical"}">{quality["data_completeness"]["cvss_coverage"]:.1f}%</div>
                <div class="metric-label">CVSS Coverage</div>
            </div>
            <div class="metric-card">
                <div class="metric-value {"good" if quality["data_completeness"]["vendor_identification"] >= 80 else "warning" if quality["data_completeness"]["vendor_identification"] >= 60 else "critical"}">{quality["data_completeness"]["vendor_identification"]:.1f}%</div>
                <div class="metric-label">Vendor Identification</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>🎯 EPSS Score Distribution</h2>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">{epss["epss_statistics"].get("min", 0):.3f}</div>
                <div class="metric-label">Minimum EPSS</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{epss["epss_statistics"].get("max", 0):.3f}</div>
                <div class="metric-label">Maximum EPSS</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{epss["epss_statistics"].get("mean", 0):.3f}</div>
                <div class="metric-label">Average EPSS</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{epss["epss_statistics"].get("median", 0):.3f}</div>
                <div class="metric-label">Median EPSS</div>
            </div>
        </div>

        <h3>Distribution by Ranges</h3>
        <table>
            <thead>
                <tr><th>EPSS Range</th><th>Count</th><th>Percentage</th><th>Distribution</th></tr>
            </thead>
            <tbody>"""

        for range_label, range_data in epss["distribution_ranges"].items():
            percentage = range_data["percentage"]
            html += f"""
                <tr>
                    <td>{range_label}</td>
                    <td>{range_data["count"]:,}</td>
                    <td>{percentage:.1f}%</td>
                    <td>
                        <div class="distribution-bar">
                            <div class="distribution-fill" style="width: {percentage}%"></div>
                        </div>
                    </td>
                </tr>"""

        html += """
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>🏢 Top Vendors</h2>
        <table>
            <thead>
                <tr><th>Vendor</th><th>Vulnerability Count</th><th>Percentage</th></tr>
            </thead>
            <tbody>"""

        for vendor_data in report["vendor_analysis"]["top_vendors"]:
            html += f"""
                <tr>
                    <td>{vendor_data["vendor"]}</td>
                    <td>{vendor_data["count"]:,}</td>
                    <td>{vendor_data["percentage"]:.1f}%</td>
                </tr>"""

        html += f"""
            </tbody>
        </table>
        <p><em>Unknown/Missing vendors: {report["vendor_analysis"]["unknown_vendors"]:,}</em></p>
    </div>

    <div class="section">
        <h2>⚠️ Severity Distribution</h2>
        <table>
            <thead>
                <tr><th>Severity</th><th>Count</th><th>Percentage</th></tr>
            </thead>
            <tbody>"""

        for severity, data in report["severity_analysis"]["distribution"].items():
            if data["count"] > 0:
                html += f"""
                    <tr>
                        <td><strong>{severity}</strong></td>
                        <td>{data["count"]:,}</td>
                        <td>{data["percentage"]:.1f}%</td>
                    </tr>"""

        html += """
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>📈 EPSS Threshold Compliance</h2>
        <table>
            <thead>
                <tr><th>Threshold</th><th>Compliant CVEs</th><th>Compliance Rate</th></tr>
            </thead>
            <tbody>"""

        for threshold, data in epss["threshold_compliance"].items():
            html += f"""
                <tr>
                    <td>≥{threshold}</td>
                    <td>{data["count"]:,}</td>
                    <td>{data["percentage"]:.1f}%</td>
                </tr>"""

        html += """
            </tbody>
        </table>
    </div>

    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em;">
        <p>Generated by Vuln-Bot Data Quality Report Agent • <a href="https://github.com/williamzujkowski/vuln-bot">GitHub</a></p>
    </footer>

</body>
</html>"""

        return html

    def _extract_epss_score(self, vuln: Dict[str, Any]) -> Optional[float]:
        """Extract EPSS score from vulnerability data."""
        # Direct score fields
        if "epssScore" in vuln and vuln["epssScore"] is not None:
            try:
                score = float(vuln["epssScore"])
                # Convert percentage to decimal if needed
                return score / 100.0 if score > 1.0 else score
            except (ValueError, TypeError):
                pass

        if "epss_score" in vuln and vuln["epss_score"] is not None:
            try:
                score = float(vuln["epss_score"])
                return score / 100.0 if score > 1.0 else score
            except (ValueError, TypeError):
                pass

        # Nested score objects
        if isinstance(vuln.get("epssScore"), dict) and "score" in vuln["epssScore"]:
            try:
                return float(vuln["epssScore"]["score"])
            except (ValueError, TypeError):
                pass

        if isinstance(vuln.get("epss"), dict) and "score" in vuln["epss"]:
            try:
                return float(vuln["epss"]["score"])
            except (ValueError, TypeError):
                pass

        # Fall back to percentile / 100 if available
        if "epssPercentile" in vuln and vuln["epssPercentile"] is not None:
            try:
                return float(vuln["epssPercentile"]) / 100.0
            except (ValueError, TypeError):
                pass

        return None

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute data quality report generation task.

        Args:
            task: Task containing 'vulnerabilities' and optional 'harvest_metadata'

        Returns:
            Dictionary with report paths and summary
        """
        vulnerabilities = task.get("vulnerabilities", [])
        harvest_metadata = task.get("harvest_metadata", {})

        # Generate comprehensive report
        report = self.generate_quality_report(vulnerabilities, harvest_metadata)

        # Save in multiple formats
        json_path = self.save_report_json(report)
        html_path = self.save_report_html(report)

        # Also save daily report with standard name
        daily_json = self.save_report_json(report, "epss-quality-daily.json")
        daily_html = self.save_report_html(report, "epss-quality-daily.html")

        return {
            "report_generated": True,
            "files": {
                "json": str(json_path),
                "html": str(html_path),
                "daily_json": str(daily_json),
                "daily_html": str(daily_html),
            },
            "summary": report["quality_summary"],
            "vulnerabilities_analyzed": len(vulnerabilities),
        }

    def get_dependencies(self) -> List[str]:
        """Get agent dependencies."""
        return []
