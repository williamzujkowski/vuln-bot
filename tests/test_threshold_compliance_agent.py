#!/usr/bin/env python3
"""
Tests for ThresholdComplianceAgent.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts.agents.threshold_compliance_agent import ThresholdComplianceAgent


class TestThresholdComplianceAgent:
    """Tests for ThresholdComplianceAgent."""

    def test_init_default_threshold(self):
        """Test agent initialization with default threshold."""
        agent = ThresholdComplianceAgent()
        assert agent.min_epss_threshold == 0.6
        assert agent.min_epss_percentage == 60

    def test_init_custom_threshold(self):
        """Test agent initialization with custom threshold."""
        agent = ThresholdComplianceAgent(min_epss_threshold=0.8)
        assert agent.min_epss_threshold == 0.8
        assert agent.min_epss_percentage == 80

    def test_validate_vulnerability_compliance_passing(self):
        """Test vulnerability compliance validation with passing data."""
        agent = ThresholdComplianceAgent(min_epss_threshold=0.6)
        
        vulnerabilities = [
            {"cveId": "CVE-2025-0001", "epssScore": 75.5, "severity": "CRITICAL"},
            {"cveId": "CVE-2025-0002", "epssScore": 0.8, "severity": "HIGH"},  # decimal format
            {"cveId": "CVE-2025-0003", "epssScore": 90.2, "severity": "CRITICAL"},
        ]
        
        result = agent.validate_vulnerability_compliance(vulnerabilities)
        
        assert result["passed"] is True
        assert result["total_vulnerabilities"] == 3
        assert result["compliant_vulnerabilities"] == 3
        assert result["non_compliant_vulnerabilities"] == 0
        assert len(result["violations"]) == 0
        assert result["statistics"]["min_epss"] == 0.755  # 75.5% -> 0.755
        assert result["statistics"]["max_epss"] == 0.902  # 90.2% -> 0.902

    def test_validate_vulnerability_compliance_failing(self):
        """Test vulnerability compliance validation with failing data."""
        agent = ThresholdComplianceAgent(min_epss_threshold=0.7)
        
        vulnerabilities = [
            {"cveId": "CVE-2025-0001", "epssScore": 75.5, "severity": "CRITICAL"},  # Pass
            {"cveId": "CVE-2025-0002", "epssScore": 55.2, "severity": "HIGH"},     # Fail
            {"cveId": "CVE-2025-0003", "epssScore": 60.1, "severity": "MEDIUM"},   # Fail
        ]
        
        result = agent.validate_vulnerability_compliance(vulnerabilities)
        
        assert result["passed"] is False
        assert result["total_vulnerabilities"] == 3
        assert result["compliant_vulnerabilities"] == 1
        assert result["non_compliant_vulnerabilities"] == 2
        assert len(result["violations"]) == 2
        
        # Check violation details
        violations = result["violations"]
        assert violations[0]["cve_id"] == "CVE-2025-0002"
        assert violations[0]["epss_percentage"] == 55.2
        assert "55.2% < 70%" in violations[0]["threshold_violation"]
        
        assert violations[1]["cve_id"] == "CVE-2025-0003"
        assert abs(violations[1]["epss_percentage"] - 60.1) < 0.01  # Handle floating point precision
        assert "60.1% < 70%" in violations[1]["threshold_violation"]

    def test_validate_vulnerability_compliance_missing_epss(self):
        """Test vulnerability compliance validation with missing EPSS scores."""
        agent = ThresholdComplianceAgent(min_epss_threshold=0.6)
        
        vulnerabilities = [
            {"cveId": "CVE-2025-0001", "epssScore": 75.5, "severity": "CRITICAL"},  # Pass
            {"cveId": "CVE-2025-0002", "severity": "HIGH"},                         # Missing EPSS
            {"cveId": "CVE-2025-0003", "epssScore": None, "severity": "MEDIUM"},    # Null EPSS
        ]
        
        result = agent.validate_vulnerability_compliance(vulnerabilities)
        
        assert result["passed"] is False
        assert result["total_vulnerabilities"] == 3
        assert result["compliant_vulnerabilities"] == 1
        assert result["non_compliant_vulnerabilities"] == 2
        assert len(result["violations"]) == 2
        
        # Check missing EPSS violations
        violations = result["violations"]
        missing_violations = [v for v in violations if v["threshold_violation"] == "Missing EPSS score"]
        assert len(missing_violations) == 2

    def test_validate_api_files_success(self):
        """Test API files validation with compliant data."""
        agent = ThresholdComplianceAgent(min_epss_threshold=0.6)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            api_dir = Path(temp_dir)
            vulns_dir = api_dir / "vulns"
            vulns_dir.mkdir()
            
            # Create index file with compliant vulnerabilities
            index_data = {
                "vulnerabilities": [
                    {"cveId": "CVE-2025-0001", "epssScore": 75.5, "severity": "CRITICAL"},
                    {"cveId": "CVE-2025-0002", "epssScore": 80.2, "severity": "HIGH"},
                ]
            }
            
            index_file = vulns_dir / "index.json"
            with open(index_file, 'w') as f:
                json.dump(index_data, f)
            
            result = agent.validate_api_files(api_dir)
            
            assert result["passed"] is True
            assert result["total_vulnerabilities"] == 2
            assert result["compliant_vulnerabilities"] == 2
            assert result["non_compliant_vulnerabilities"] == 0
            assert result["files_checked"] == 1
            assert len(result["violations"]) == 0

    def test_validate_api_files_with_chunks(self):
        """Test API files validation with chunk files."""
        agent = ThresholdComplianceAgent(min_epss_threshold=0.6)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            api_dir = Path(temp_dir)
            vulns_dir = api_dir / "vulns"
            vulns_dir.mkdir()
            
            # Create chunk index
            chunk_index = {
                "chunks": [
                    {"file": "vulns-2025-CRITICAL.json", "severity": "CRITICAL", "count": 2},
                    {"file": "vulns-2025-HIGH.json", "severity": "HIGH", "count": 1}
                ]
            }
            
            chunk_index_file = vulns_dir / "chunk-index.json"
            with open(chunk_index_file, 'w') as f:
                json.dump(chunk_index, f)
            
            # Create chunk files
            critical_data = {
                "vulnerabilities": [
                    {"cveId": "CVE-2025-0001", "epssScore": 85.5, "severity": "CRITICAL"},
                    {"cveId": "CVE-2025-0002", "epssScore": 90.2, "severity": "CRITICAL"},
                ]
            }
            
            high_data = {
                "vulnerabilities": [
                    {"cveId": "CVE-2025-0003", "epssScore": 70.1, "severity": "HIGH"},
                ]
            }
            
            with open(vulns_dir / "vulns-2025-CRITICAL.json", 'w') as f:
                json.dump(critical_data, f)
            
            with open(vulns_dir / "vulns-2025-HIGH.json", 'w') as f:
                json.dump(high_data, f)
            
            result = agent.validate_api_files(api_dir)
            
            assert result["passed"] is True
            assert result["total_vulnerabilities"] == 3
            assert result["compliant_vulnerabilities"] == 3
            assert result["non_compliant_vulnerabilities"] == 0
            assert result["files_checked"] == 2  # Only chunk files, no index
            assert len(result["violations"]) == 0

    def test_validate_api_files_violations(self):
        """Test API files validation with violations."""
        agent = ThresholdComplianceAgent(min_epss_threshold=0.8)  # High threshold
        
        with tempfile.TemporaryDirectory() as temp_dir:
            api_dir = Path(temp_dir)
            vulns_dir = api_dir / "vulns"
            vulns_dir.mkdir()
            
            # Create index file with some non-compliant vulnerabilities
            index_data = {
                "vulnerabilities": [
                    {"cveId": "CVE-2025-0001", "epssScore": 85.5, "severity": "CRITICAL"},  # Pass
                    {"cveId": "CVE-2025-0002", "epssScore": 70.2, "severity": "HIGH"},     # Fail
                    {"cveId": "CVE-2025-0003", "epssScore": 60.1, "severity": "MEDIUM"},   # Fail
                ]
            }
            
            index_file = vulns_dir / "index.json"
            with open(index_file, 'w') as f:
                json.dump(index_data, f)
            
            result = agent.validate_api_files(api_dir)
            
            assert result["passed"] is False
            assert result["total_vulnerabilities"] == 3
            assert result["compliant_vulnerabilities"] == 1
            assert result["non_compliant_vulnerabilities"] == 2
            assert len(result["violations"]) == 2

    def test_validate_api_files_missing_directory(self):
        """Test API files validation with missing directory."""
        agent = ThresholdComplianceAgent()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            api_dir = Path(temp_dir) / "nonexistent"
            
            result = agent.validate_api_files(api_dir)
            
            assert result["passed"] is False
            assert "API directory not found" in result["error"]

    def test_extract_epss_score_formats(self):
        """Test EPSS score extraction from different formats."""
        agent = ThresholdComplianceAgent()
        
        # Test direct score fields
        assert agent._extract_epss_score({"epssScore": 75.5}) == 0.755  # percentage to decimal
        assert agent._extract_epss_score({"epssScore": 0.755}) == 0.755  # already decimal
        assert agent._extract_epss_score({"epss_score": 80.2}) == 0.802
        
        # Test nested objects
        assert agent._extract_epss_score({"epssScore": {"score": 0.65}}) == 0.65
        assert agent._extract_epss_score({"epss": {"score": 0.78}}) == 0.78
        
        # Test percentile fallback
        assert agent._extract_epss_score({"epssPercentile": 85.5}) == 0.855
        
        # Test missing/invalid scores
        assert agent._extract_epss_score({}) is None
        assert agent._extract_epss_score({"epssScore": None}) is None
        assert agent._extract_epss_score({"epssScore": "invalid"}) is None

    def test_generate_compliance_report(self):
        """Test compliance report generation."""
        agent = ThresholdComplianceAgent(min_epss_threshold=0.7)
        
        validation_result = {
            "passed": False,
            "total_vulnerabilities": 5,
            "compliant_vulnerabilities": 3,
            "non_compliant_vulnerabilities": 2,
            "violations": [
                {
                    "cve_id": "CVE-2025-0001",
                    "epss_score": 0.65,
                    "epss_percentage": 65.0,
                    "threshold_violation": "EPSS 65.0% < 70%",
                    "severity": "HIGH"
                },
                {
                    "cve_id": "CVE-2025-0002",
                    "epss_score": None,
                    "epss_percentage": None,
                    "threshold_violation": "Missing EPSS score",
                    "severity": "CRITICAL"
                }
            ],
            "statistics": {
                "min_epss": 0.65,
                "max_epss": 0.85,
                "avg_epss": 0.75,
                "epss_coverage": 80.0
            }
        }
        
        report = agent.generate_compliance_report(validation_result)
        
        assert "EPSS THRESHOLD COMPLIANCE REPORT" in report
        assert "≥70% EPSS score" in report
        assert "Total vulnerabilities: 5" in report
        assert "Compliant: 3" in report
        assert "Non-compliant: 2" in report
        assert "❌ FAILED" in report
        assert "EPSS Coverage: 80.0%" in report
        assert "CVE-2025-0001 - EPSS 65.0% < 70%" in report
        assert "CVE-2025-0002 - Missing EPSS score" in report

    def test_save_compliance_report(self):
        """Test saving compliance reports."""
        agent = ThresholdComplianceAgent()
        
        validation_result = {
            "passed": True,
            "total_vulnerabilities": 2,
            "compliant_vulnerabilities": 2,
            "non_compliant_vulnerabilities": 0,
            "violations": [],
            "statistics": {"min_epss": 0.7, "max_epss": 0.9, "avg_epss": 0.8, "epss_coverage": 100.0}
        }
        
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            
            json_path, txt_path = agent.save_compliance_report(validation_result, output_dir)
            
            # Check files were created
            assert json_path.exists()
            assert txt_path.exists()
            
            # Check daily files were created
            daily_json = output_dir / "epss_compliance_daily.json"
            daily_txt = output_dir / "epss_compliance_daily.txt"
            assert daily_json.exists()
            assert daily_txt.exists()
            
            # Check JSON content
            with open(json_path) as f:
                saved_data = json.load(f)
                assert saved_data["passed"] is True
                assert saved_data["total_vulnerabilities"] == 2
            
            # Check text content
            with open(txt_path) as f:
                report_text = f.read()
                assert "✅ PASSED" in report_text
                assert "Total vulnerabilities: 2" in report_text

    @pytest.mark.asyncio
    async def test_execute_with_vulnerabilities(self):
        """Test agent execution with vulnerability list."""
        agent = ThresholdComplianceAgent(min_epss_threshold=0.6)
        
        task = {
            "vulnerabilities": [
                {"cveId": "CVE-2025-0001", "epssScore": 75.5, "severity": "CRITICAL"},
                {"cveId": "CVE-2025-0002", "epssScore": 80.2, "severity": "HIGH"},
            ],
            "output_dir": "test_reports"
        }
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Override output dir for test
            task["output_dir"] = temp_dir
            
            result = await agent.execute(task)
            
            assert result["validation_passed"] is True
            assert result["total_vulnerabilities"] == 2
            assert result["violations_count"] == 0
            assert result["compliance_rate"] == 100.0
            assert "reports" in result
            assert "json" in result["reports"]
            assert "txt" in result["reports"]

    @pytest.mark.asyncio
    async def test_execute_with_api_dir(self):
        """Test agent execution with API directory."""
        agent = ThresholdComplianceAgent(min_epss_threshold=0.7)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            api_dir = Path(temp_dir) / "api"
            vulns_dir = api_dir / "vulns"
            vulns_dir.mkdir(parents=True)
            
            # Create test API file
            index_data = {
                "vulnerabilities": [
                    {"cveId": "CVE-2025-0001", "epssScore": 85.5, "severity": "CRITICAL"},
                    {"cveId": "CVE-2025-0002", "epssScore": 60.2, "severity": "HIGH"},  # Violation
                ]
            }
            
            with open(vulns_dir / "index.json", 'w') as f:
                json.dump(index_data, f)
            
            task = {
                "api_dir": str(api_dir),
                "output_dir": temp_dir
            }
            
            result = await agent.execute(task)
            
            assert result["validation_passed"] is False
            assert result["total_vulnerabilities"] == 2
            assert result["violations_count"] == 1
            assert result["compliance_rate"] == 50.0

    def test_get_dependencies(self):
        """Test agent dependencies."""
        agent = ThresholdComplianceAgent()
        dependencies = agent.get_dependencies()
        assert dependencies == []


if __name__ == "__main__":
    pytest.main([__file__])