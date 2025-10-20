#!/usr/bin/env python3
"""
ThresholdComplianceAgent - Validates EPSS threshold compliance for CI/CD gating.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scripts.agents.base_agent import BaseAgent


class ThresholdComplianceAgent(BaseAgent):
    """Agent for validating EPSS threshold compliance in CI/CD pipelines."""

    def __init__(
        self, cache_dir: Optional[Path] = None, min_epss_threshold: float = 0.6
    ):
        """
        Initialize Threshold Compliance Agent.

        Args:
            cache_dir: Directory for caching results
            min_epss_threshold: Minimum EPSS threshold (0.0-1.0, default: 0.6 for 60%)
        """
        super().__init__(name="ThresholdComplianceAgent", cache_dir=cache_dir)

        self.min_epss_threshold = min_epss_threshold
        self.min_epss_percentage = int(min_epss_threshold * 100)

        self.logger.info(
            "Threshold Compliance Agent initialized",
            min_epss_threshold=min_epss_threshold,
            min_epss_percentage=self.min_epss_percentage,
        )

    def validate_vulnerability_compliance(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Validate that all vulnerabilities meet the EPSS threshold.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with compliance validation results
        """
        validation_result = {
            "passed": True,
            "total_vulnerabilities": len(vulnerabilities),
            "compliant_vulnerabilities": 0,
            "non_compliant_vulnerabilities": 0,
            "violations": [],
            "threshold": {
                "decimal": self.min_epss_threshold,
                "percentage": self.min_epss_percentage,
            },
            "statistics": {
                "min_epss": None,
                "max_epss": None,
                "avg_epss": None,
                "epss_coverage": 0,
            },
        }

        epss_scores = []
        violations = []

        for vuln in vulnerabilities:
            epss_score = self._extract_epss_score(vuln)

            if epss_score is not None:
                epss_scores.append(epss_score)

                # Convert to percentage for comparison
                epss_percentage = epss_score * 100 if epss_score <= 1.0 else epss_score

                if epss_score < self.min_epss_threshold:
                    violations.append(
                        {
                            "cve_id": vuln.get("cveId")
                            or vuln.get("cve_id")
                            or "Unknown",
                            "epss_score": epss_score,
                            "epss_percentage": epss_percentage,
                            "threshold_violation": f"EPSS {epss_percentage:.1f}% < {self.min_epss_percentage}%",
                            "severity": vuln.get("severity", "Unknown"),
                            "title": vuln.get("title", "No title available")[:100],
                        }
                    )
                    validation_result["non_compliant_vulnerabilities"] += 1
                else:
                    validation_result["compliant_vulnerabilities"] += 1
            else:
                # Missing EPSS score is also a violation
                violations.append(
                    {
                        "cve_id": vuln.get("cveId") or vuln.get("cve_id") or "Unknown",
                        "epss_score": None,
                        "epss_percentage": None,
                        "threshold_violation": "Missing EPSS score",
                        "severity": vuln.get("severity", "Unknown"),
                        "title": vuln.get("title", "No title available")[:100],
                    }
                )
                validation_result["non_compliant_vulnerabilities"] += 1

        # Calculate statistics
        if epss_scores:
            validation_result["statistics"].update(
                {
                    "min_epss": min(epss_scores),
                    "max_epss": max(epss_scores),
                    "avg_epss": sum(epss_scores) / len(epss_scores),
                    "epss_coverage": len(epss_scores) / len(vulnerabilities) * 100,
                }
            )

        validation_result["violations"] = violations
        validation_result["passed"] = len(violations) == 0

        self.logger.info(
            "Threshold compliance validation completed",
            total_vulnerabilities=validation_result["total_vulnerabilities"],
            compliant=validation_result["compliant_vulnerabilities"],
            violations=len(violations),
            passed=validation_result["passed"],
        )

        return validation_result

    def validate_api_files(self, api_dir: Path) -> Dict[str, Any]:
        """
        Validate EPSS compliance in generated API files.

        Args:
            api_dir: Directory containing API files

        Returns:
            Dictionary with API validation results
        """
        validation_result = {
            "passed": True,
            "files_checked": 0,
            "vulnerabilities_checked": 0,
            "violations": [],
            "files": {},
            "total_vulnerabilities": 0,
            "compliant_vulnerabilities": 0,
            "non_compliant_vulnerabilities": 0,
            "threshold": {
                "decimal": self.min_epss_threshold,
                "percentage": self.min_epss_percentage,
            },
            "statistics": {
                "min_epss": None,
                "max_epss": None,
                "avg_epss": None,
                "epss_coverage": 0,
            },
        }

        api_vulns_dir = api_dir / "vulns"
        if not api_vulns_dir.exists():
            validation_result["passed"] = False
            validation_result["error"] = f"API directory not found: {api_vulns_dir}"
            return validation_result

        all_epss_scores = []

        # Check index file
        index_file = api_vulns_dir / "index.json"
        if index_file.exists():
            try:
                with open(index_file) as f:
                    index_data = json.load(f)
                    vulnerabilities = index_data.get("vulnerabilities", [])

                    file_result = self.validate_vulnerability_compliance(
                        vulnerabilities
                    )
                    validation_result["files"]["index.json"] = file_result
                    validation_result["files_checked"] += 1
                    validation_result["vulnerabilities_checked"] += len(vulnerabilities)

                    # Aggregate results
                    validation_result["total_vulnerabilities"] += file_result[
                        "total_vulnerabilities"
                    ]
                    validation_result["compliant_vulnerabilities"] += file_result[
                        "compliant_vulnerabilities"
                    ]
                    validation_result["non_compliant_vulnerabilities"] += file_result[
                        "non_compliant_vulnerabilities"
                    ]
                    validation_result["violations"].extend(file_result["violations"])

                    # Collect EPSS scores for overall statistics
                    for vuln in vulnerabilities:
                        epss_score = self._extract_epss_score(vuln)
                        if epss_score is not None:
                            all_epss_scores.append(epss_score)

                    if not file_result["passed"]:
                        validation_result["passed"] = False

            except Exception as e:
                validation_result["passed"] = False
                validation_result["files"]["index.json"] = {"error": str(e)}

        # Check chunk files
        chunk_index_file = api_vulns_dir / "chunk-index.json"
        if chunk_index_file.exists():
            try:
                with open(chunk_index_file) as f:
                    chunk_index = json.load(f)
                    chunks = chunk_index.get("chunks", [])

                    for chunk in chunks:
                        chunk_file = chunk.get("file")
                        if chunk_file:
                            chunk_path = api_vulns_dir / chunk_file
                            if chunk_path.exists():
                                try:
                                    with open(chunk_path) as cf:
                                        chunk_data = json.load(cf)
                                        vulnerabilities = chunk_data.get(
                                            "vulnerabilities", []
                                        )

                                        file_result = (
                                            self.validate_vulnerability_compliance(
                                                vulnerabilities
                                            )
                                        )
                                        validation_result["files"][
                                            chunk_file
                                        ] = file_result
                                        validation_result["files_checked"] += 1
                                        validation_result[
                                            "vulnerabilities_checked"
                                        ] += len(vulnerabilities)

                                        # Aggregate results
                                        validation_result[
                                            "total_vulnerabilities"
                                        ] += file_result["total_vulnerabilities"]
                                        validation_result[
                                            "compliant_vulnerabilities"
                                        ] += file_result["compliant_vulnerabilities"]
                                        validation_result[
                                            "non_compliant_vulnerabilities"
                                        ] += file_result[
                                            "non_compliant_vulnerabilities"
                                        ]
                                        validation_result["violations"].extend(
                                            file_result["violations"]
                                        )

                                        # Collect EPSS scores for overall statistics
                                        for vuln in vulnerabilities:
                                            epss_score = self._extract_epss_score(vuln)
                                            if epss_score is not None:
                                                all_epss_scores.append(epss_score)

                                        if not file_result["passed"]:
                                            validation_result["passed"] = False

                                except Exception as e:
                                    validation_result["passed"] = False
                                    validation_result["files"][chunk_file] = {
                                        "error": str(e)
                                    }

            except Exception as e:
                validation_result["passed"] = False
                validation_result["chunk_index_error"] = str(e)

        # Calculate overall statistics
        if all_epss_scores:
            validation_result["statistics"].update(
                {
                    "min_epss": min(all_epss_scores),
                    "max_epss": max(all_epss_scores),
                    "avg_epss": sum(all_epss_scores) / len(all_epss_scores),
                    "epss_coverage": len(all_epss_scores)
                    / max(validation_result["total_vulnerabilities"], 1)
                    * 100,
                }
            )

        # Update final passed status
        validation_result["passed"] = len(validation_result["violations"]) == 0

        return validation_result

    def generate_compliance_report(self, validation_result: Dict[str, Any]) -> str:
        """
        Generate a human-readable compliance report.

        Args:
            validation_result: Result from validation methods

        Returns:
            Formatted compliance report string
        """
        report_lines = [
            "=" * 60,
            "🛡️  EPSS THRESHOLD COMPLIANCE REPORT",
            "=" * 60,
            f"Timestamp: {datetime.now(timezone.utc).isoformat()}",
            f"Threshold: ≥{self.min_epss_percentage}% EPSS score",
            "",
            "📊 SUMMARY:",
            f"  Total vulnerabilities: {validation_result['total_vulnerabilities']:,}",
            f"  Compliant: {validation_result['compliant_vulnerabilities']:,}",
            f"  Non-compliant: {validation_result['non_compliant_vulnerabilities']:,}",
            f"  Overall status: {'✅ PASSED' if validation_result['passed'] else '❌ FAILED'}",
        ]

        # Add statistics if available
        stats = validation_result.get("statistics", {})
        if stats.get("min_epss") is not None:
            report_lines.extend(
                [
                    "",
                    "📈 EPSS STATISTICS:",
                    f"  EPSS Coverage: {stats['epss_coverage']:.1f}%",
                    f"  EPSS Range: {stats['min_epss']:.3f} - {stats['max_epss']:.3f}",
                    f"  Average EPSS: {stats['avg_epss']:.3f}",
                ]
            )

        # Add violations if any
        violations = validation_result.get("violations", [])
        if violations:
            report_lines.extend(
                [
                    "",
                    f"🚨 VIOLATIONS ({len(violations)}):",
                ]
            )

            for i, violation in enumerate(violations[:10], 1):  # Show first 10
                cve_id = violation["cve_id"]
                violation_desc = violation["threshold_violation"]
                severity = violation.get("severity", "Unknown")

                report_lines.append(
                    f"  {i}. {cve_id} - {violation_desc} (Severity: {severity})"
                )

            if len(violations) > 10:
                report_lines.append(f"  ... and {len(violations) - 10} more violations")

        # Add file-specific results if available
        files_data = validation_result.get("files", {})
        if files_data:
            report_lines.extend(
                [
                    "",
                    f"📁 FILES CHECKED ({validation_result.get('files_checked', 0)}):",
                ]
            )

            for filename, file_result in files_data.items():
                if isinstance(file_result, dict) and "passed" in file_result:
                    status = "✅" if file_result["passed"] else "❌"
                    violations_count = len(file_result.get("violations", []))
                    total_vulns = file_result.get("total_vulnerabilities", 0)
                    report_lines.append(
                        f"  {status} {filename}: {total_vulns} vulns, {violations_count} violations"
                    )
                else:
                    report_lines.append(
                        f"  ❌ {filename}: {file_result.get('error', 'Unknown error')}"
                    )

        report_lines.extend(
            [
                "",
                "=" * 60,
            ]
        )

        return "\n".join(report_lines)

    def save_compliance_report(
        self, validation_result: Dict[str, Any], output_dir: Path
    ) -> Tuple[Path, Path]:
        """
        Save compliance report in JSON and text formats.

        Args:
            validation_result: Validation result dictionary
            output_dir: Directory to save reports

        Returns:
            Tuple of (json_path, txt_path)
        """
        output_dir.mkdir(exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save JSON report
        json_path = output_dir / f"epss_compliance_{timestamp}.json"
        with open(json_path, "w") as f:
            json.dump(validation_result, f, indent=2, default=str)

        # Save text report
        txt_path = output_dir / f"epss_compliance_{timestamp}.txt"
        report_text = self.generate_compliance_report(validation_result)
        with open(txt_path, "w") as f:
            f.write(report_text)

        # Also save daily report with standard name
        daily_json = output_dir / "epss_compliance_daily.json"
        daily_txt = output_dir / "epss_compliance_daily.txt"

        with open(daily_json, "w") as f:
            json.dump(validation_result, f, indent=2, default=str)

        with open(daily_txt, "w") as f:
            f.write(report_text)

        self.logger.info(
            "Compliance reports saved", json_path=str(json_path), txt_path=str(txt_path)
        )

        return json_path, txt_path

    def _extract_epss_score(self, vuln: Dict[str, Any]) -> Optional[float]:
        """Extract EPSS score from vulnerability data."""
        # Direct score fields
        if "epssScore" in vuln and vuln["epssScore"] is not None:
            try:
                score = float(vuln["epssScore"])
                # Convert percentage to decimal if needed (scores > 1.0 are percentages)
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
        Execute threshold compliance validation task.

        Args:
            task: Task containing 'vulnerabilities' or 'api_dir' to validate

        Returns:
            Dictionary with validation results and report paths
        """
        vulnerabilities = task.get("vulnerabilities")
        api_dir = task.get("api_dir")
        output_dir = Path(task.get("output_dir", "reports"))

        if vulnerabilities:
            # Validate vulnerability list directly
            validation_result = self.validate_vulnerability_compliance(vulnerabilities)
        elif api_dir:
            # Validate API files
            validation_result = self.validate_api_files(Path(api_dir))
        else:
            raise ValueError("Task must contain either 'vulnerabilities' or 'api_dir'")

        # Save reports
        json_path, txt_path = self.save_compliance_report(validation_result, output_dir)

        return {
            "validation_passed": validation_result["passed"],
            "total_vulnerabilities": validation_result.get("total_vulnerabilities", 0),
            "violations_count": len(validation_result.get("violations", [])),
            "compliance_rate": (
                validation_result.get("compliant_vulnerabilities", 0)
                / max(validation_result.get("total_vulnerabilities", 1), 1)
            )
            * 100,
            "reports": {"json": str(json_path), "txt": str(txt_path)},
            "validation_result": validation_result,
        }

    def get_dependencies(self) -> List[str]:
        """Get agent dependencies."""
        return []
