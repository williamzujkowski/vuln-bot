"""Tests for the briefing generator."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.models import (
    CVSSMetric,
    EPSSScore,
    ExploitationStatus,
    Reference,
    SeverityLevel,
    Vulnerability,
    VulnerabilityBatch,
    VulnerabilitySource,
)
from scripts.processing.briefing_generator import BriefingGenerator


@pytest.fixture
def output_dir(tmp_path):
    """Create temporary output directory."""
    output = tmp_path / "output"
    output.mkdir()
    return output


@pytest.fixture
def briefing_generator(output_dir):
    """Create briefing generator instance."""
    return BriefingGenerator(output_dir)


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerabilities for testing."""
    base_date = datetime.now(timezone.utc)

    return [
        Vulnerability(
            cve_id="CVE-2025-1001",
            title="Critical Remote Code Execution",
            description="A critical vulnerability allowing remote code execution.",
            published_date=base_date,
            last_modified_date=base_date,
            severity=SeverityLevel.CRITICAL,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=9.8,
                    base_severity="CRITICAL",
                )
            ],
            epss_score=EPSSScore(
                cve_id="CVE-2025-1001",
                score=0.95,
                percentile=0.99,
                date=base_date.date(),
            ),
            risk_score=95,
            affected_vendors=["vendor1"],
            affected_products=["product1"],
            references=[
                Reference(
                    url="https://vendor1.com/advisory/1001",
                    source="vendor1",
                    tags=["Vendor Advisory"],
                )
            ],
            exploitation_status=ExploitationStatus.ACTIVE,
            sources=[
                VulnerabilitySource(
                    name="CVEList",
                    url="https://example.com/cve-2025-1001",
                    last_modified=base_date,
                )
            ],
            tags=["CWE-78", "RCE"],
        ),
        Vulnerability(
            cve_id="CVE-2025-1002",
            title="High Severity SQL Injection",
            description="SQL injection vulnerability in web application.",
            published_date=base_date,
            last_modified_date=base_date,
            severity=SeverityLevel.HIGH,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    base_score=8.1,
                    base_severity="HIGH",
                )
            ],
            epss_score=EPSSScore(
                cve_id="CVE-2025-1002",
                score=0.75,
                percentile=0.90,
                date=base_date.date(),
            ),
            risk_score=80,
            affected_vendors=["vendor2"],
            affected_products=["webapp"],
            references=[
                Reference(
                    url="https://nvd.nist.gov/vuln/detail/CVE-2025-1002",
                    source="NVD",
                    tags=["Technical Description"],
                )
            ],
            exploitation_status=ExploitationStatus.POC,
            sources=[
                VulnerabilitySource(
                    name="CVEList",
                    url="https://example.com/cve-2025-1002",
                    last_modified=base_date,
                )
            ],
            tags=["CWE-89", "SQLi"],
        ),
        Vulnerability(
            cve_id="CVE-2025-1003",
            title="Medium Severity XSS",
            description="Cross-site scripting vulnerability.",
            published_date=base_date,
            last_modified_date=base_date,
            severity=SeverityLevel.MEDIUM,
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    base_score=6.1,
                    base_severity="MEDIUM",
                )
            ],
            epss_score=EPSSScore(
                cve_id="CVE-2025-1003",
                score=0.25,
                percentile=0.65,
                date=base_date.date(),
            ),
            risk_score=45,
            affected_vendors=["vendor3"],
            affected_products=["browser"],
            references=[],
            exploitation_status=ExploitationStatus.NONE,
            sources=[
                VulnerabilitySource(
                    name="CVEList",
                    url="https://example.com/cve-2025-1003",
                    last_modified=base_date,
                )
            ],
            tags=["CWE-79"],
        ),
    ]


@pytest.fixture
def sample_batch(sample_vulnerabilities):
    """Create sample vulnerability batch."""
    return VulnerabilityBatch(
        vulnerabilities=sample_vulnerabilities,
        metadata={
            "harvest_id": "test-harvest-123",
            "start_time": datetime.now(timezone.utc).isoformat(),
            "end_time": datetime.now(timezone.utc).isoformat(),
            "sources": [
                {
                    "name": "cvelist",
                    "count": 3,
                    "status": "success",
                }
            ],
            "total_vulnerabilities": 3,
            "unique_vulnerabilities": 3,
        },
        harvest_date=datetime.now(timezone.utc),
    )


class TestBriefingGenerator:
    """Tests for BriefingGenerator."""

    def test_init(self, output_dir):
        """Test briefing generator initialization."""
        generator = BriefingGenerator(output_dir)
        assert generator.output_dir == output_dir
        assert generator.posts_dir == output_dir / "_posts"
        assert generator.api_dir == output_dir / "api" / "vulns"

    def test_generate_briefing_post(self, briefing_generator, sample_batch):
        """Test briefing post generation."""
        briefing_path = briefing_generator.generate_briefing_post(sample_batch)

        assert briefing_path.exists()
        assert briefing_path.suffix == ".md"
        assert "vuln-brief" in briefing_path.name

        # Check content
        content = briefing_path.read_text()
        assert "---" in content  # Front matter
        assert "Morning Vulnerability Briefing" in content
        assert "CVE-2025-1001" in content
        assert "CVE-2025-1002" in content
        assert "CVE-2025-1003" in content
        assert "**Critical Risk**: 1 vulnerabilities" in content
        assert "**High Risk**: 1 vulnerabilities" in content
        assert "Risk Score: 95" in content

    def test_generate_briefing_post_empty(self, briefing_generator):
        """Test briefing generation with no vulnerabilities."""
        empty_batch = VulnerabilityBatch(
            vulnerabilities=[],
            metadata={"total_vulnerabilities": 0},
            harvest_date=datetime.now(timezone.utc),
        )

        briefing_path = briefing_generator.generate_briefing_post(empty_batch)

        content = briefing_path.read_text()
        assert "0 vulnerabilities" in content

    def test_generate_search_index(self, briefing_generator, sample_batch):
        """Test search index generation."""
        index_path = briefing_generator.generate_search_index(sample_batch)

        assert index_path.exists()
        assert index_path == briefing_generator.api_dir / "index.json"

        # Check index content
        with open(index_path) as f:
            index_data = json.load(f)

        assert "vulnerabilities" in index_data
        assert len(index_data["vulnerabilities"]) == 3
        assert index_data["vulnerabilities"][0]["cveId"] == "CVE-2025-1001"
        assert index_data["vulnerabilities"][0]["riskScore"] == 95

    def test_generate_vulnerability_json(
        self, briefing_generator, sample_vulnerabilities
    ):
        """Test individual vulnerability JSON generation."""
        vuln = sample_vulnerabilities[0]
        json_path = briefing_generator.generate_vulnerability_json(vuln)

        assert json_path.exists()
        assert json_path == briefing_generator.api_dir / f"{vuln.cve_id}.json"

        with open(json_path) as f:
            cve_data = json.load(f)

        assert cve_data["cveId"] == vuln.cve_id
        assert cve_data["title"] == vuln.title
        assert cve_data["riskScore"] == vuln.risk_score

    def test_generate_all(self, briefing_generator, sample_batch):
        """Test generate_all method."""
        results = briefing_generator.generate_all(sample_batch, briefing_limit=2)

        assert "briefing" in results
        assert "index" in results
        assert "vulnerabilities" in results
        assert len(results["vulnerabilities"]) == 3

        # Check that files were created
        briefing_path = Path(results["briefing"])
        assert briefing_path.exists()

        index_path = Path(results["index"])
        assert index_path.exists()

        for vuln_path_str in results["vulnerabilities"]:
            vuln_path = Path(vuln_path_str)
            assert vuln_path.exists()

    def test_generate_markdown_briefing(
        self, briefing_generator, sample_vulnerabilities
    ):
        """Test markdown briefing generation."""
        from scripts.processing.risk_scorer import RiskScorer

        scorer = RiskScorer()

        briefing_data = {
            "date": datetime.now(timezone.utc),
            "date_str": "2025-06-29",
            "total_count": 3,
            "included_count": 2,
            "sources": [{"name": "cvelist", "count": 3, "status": "success"}],
            "vulnerabilities": [],
            "risk_distribution": {
                "critical": 1,
                "high": 1,
                "medium": 1,
                "low": 0,
            },
            "severity_distribution": {
                "CRITICAL": 1,
                "HIGH": 1,
                "MEDIUM": 1,
                "LOW": 0,
            },
        }

        # Add vulnerability data
        for vuln in sample_vulnerabilities[:2]:
            risk_factors = scorer.get_risk_factors(vuln)
            vuln_data = {
                "cve_id": vuln.cve_id,
                "title": vuln.title,
                "description": vuln.description,
                "risk_score": vuln.risk_score,
                "severity": vuln.severity.value,
                "cvss_score": vuln.cvss_base_score,
                "epss_score": vuln.epss_probability,
                "published_date": vuln.published_date.strftime("%Y-%m-%d"),
                "vendors": vuln.affected_vendors,
                "products": vuln.affected_products,
                "tags": vuln.tags,
                "risk_factors": list(risk_factors.values()),
                "references": [ref.url for ref in vuln.references],
            }
            briefing_data["vulnerabilities"].append(vuln_data)

        content = briefing_generator._generate_markdown_briefing(briefing_data)

        assert "Morning Vulnerability Briefing" in content
        assert "CVE-2025-1001" in content
        assert "CVE-2025-1002" in content
        assert "**Risk Score**: 95/100" in content
        assert "CRITICAL" in content
        assert "HIGH" in content

    def test_generate_briefing_with_risk_factors(
        self, briefing_generator, sample_vulnerabilities
    ):
        """Test briefing includes risk factors."""
        batch = VulnerabilityBatch(
            vulnerabilities=sample_vulnerabilities,
            metadata={
                "sources": [{"name": "cvelist", "count": 3, "status": "success"}]
            },
            harvest_date=datetime.now(timezone.utc),
        )

        briefing_path = briefing_generator.generate_briefing_post(batch)
        content = briefing_path.read_text()

        # Check risk factors are included
        assert "Risk Factors" in content
        assert "CRITICAL severity" in content
        assert "HIGH severity" in content
