"""Tests for the briefing generator."""

import json
from datetime import datetime, timezone

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
        assert generator.posts_dir == output_dir / "src" / "_posts"
        assert generator.api_dir == output_dir / "src" / "api" / "vulns"

    def test_generate_daily_briefing(self, briefing_generator, sample_batch):
        """Test daily briefing generation."""
        briefing_path = briefing_generator.generate_daily_briefing(sample_batch)

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
        assert "Critical Risk: 1" in content
        assert "High Risk: 1" in content
        assert "Risk Score: 95" in content

    def test_generate_daily_briefing_empty(self, briefing_generator):
        """Test briefing generation with no vulnerabilities."""
        empty_batch = VulnerabilityBatch(
            vulnerabilities=[],
            metadata={"total_vulnerabilities": 0},
            harvest_date=datetime.now(timezone.utc),
        )

        briefing_path = briefing_generator.generate_daily_briefing(empty_batch)

        content = briefing_path.read_text()
        assert "0 vulnerabilities" in content
        assert "No vulnerabilities" in content

    def test_generate_api_files(self, briefing_generator, sample_batch):
        """Test API file generation."""
        api_files = briefing_generator.generate_api_files(sample_batch)

        # Check index file
        index_path = briefing_generator.api_dir / "index.json"
        assert index_path.exists()
        assert index_path in api_files

        # Check index content
        with open(index_path) as f:
            index_data = json.load(f)

        assert "vulnerabilities" in index_data
        assert len(index_data["vulnerabilities"]) == 3
        assert index_data["vulnerabilities"][0]["cveId"] == "CVE-2025-1001"
        assert index_data["vulnerabilities"][0]["riskScore"] == 95

        # Check individual CVE files
        for vuln in sample_batch.vulnerabilities:
            cve_path = briefing_generator.api_dir / f"{vuln.cve_id}.json"
            assert cve_path.exists()
            assert cve_path in api_files

            with open(cve_path) as f:
                cve_data = json.load(f)

            assert cve_data["cveId"] == vuln.cve_id
            assert cve_data["title"] == vuln.title
            assert cve_data["riskScore"] == vuln.risk_score

    def test_calculate_risk_distribution(
        self, briefing_generator, sample_vulnerabilities
    ):
        """Test risk distribution calculation."""
        dist = briefing_generator._calculate_risk_distribution(sample_vulnerabilities)

        assert dist["critical"] == 1
        assert dist["high"] == 1
        assert dist["medium"] == 1
        assert dist["low"] == 0

    def test_group_by_source(self, briefing_generator, sample_vulnerabilities):
        """Test grouping vulnerabilities by source."""
        groups = briefing_generator._group_by_source(sample_vulnerabilities)

        assert "CVEList" in groups
        assert len(groups["CVEList"]) == 3

    def test_format_vulnerability_section(
        self, briefing_generator, sample_vulnerabilities
    ):
        """Test formatting vulnerability section."""
        vuln = sample_vulnerabilities[0]
        section = briefing_generator._format_vulnerability_section(vuln, 1)

        assert f"### 1. [{vuln.cve_id}]" in section
        assert "Risk Score: 95/100" in section
        assert "Severity: CRITICAL" in section
        assert "CVSS: 9.8" in section
        assert "EPSS: 95.0%" in section
        assert vuln.description in section
        assert "vendor1" in section
        assert "CWE-78" in section
        assert "https://vendor1.com/advisory/1001" in section

    def test_format_vulnerability_section_minimal(self, briefing_generator):
        """Test formatting vulnerability with minimal data."""
        vuln = Vulnerability(
            cve_id="CVE-2025-9999",
            title="Test vulnerability",
            description="Test description",
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
            severity=SeverityLevel.NONE,
            cvss_metrics=[],
            risk_score=10,
            affected_vendors=[],
            affected_products=[],
            references=[],
            sources=[],
        )

        section = briefing_generator._format_vulnerability_section(vuln, 1)

        assert "CVE-2025-9999" in section
        assert "Risk Score: 10/100" in section
        assert "CVSS: N/A" in section
        assert "EPSS: 0.0%" in section

    def test_create_front_matter(self, briefing_generator, sample_batch):
        """Test front matter creation."""
        front_matter = briefing_generator._create_front_matter(sample_batch)

        assert front_matter["layout"] == "layouts/post"
        assert front_matter["title"].startswith("Morning Vulnerability Briefing")
        assert front_matter["date"] is not None
        assert front_matter["tags"] == ["vulnerabilities", "daily-briefing"]
        assert (
            front_matter["summary"]
            == "Today's vulnerability intelligence briefing covers 3 vulnerabilities"
        )

    def test_vulnerability_to_api_dict(
        self, briefing_generator, sample_vulnerabilities
    ):
        """Test converting vulnerability to API dictionary."""
        vuln = sample_vulnerabilities[0]
        api_dict = briefing_generator._vulnerability_to_api_dict(vuln)

        assert api_dict["cveId"] == "CVE-2025-1001"
        assert api_dict["title"] == "Critical Remote Code Execution"
        assert api_dict["riskScore"] == 95
        assert api_dict["severity"] == "CRITICAL"
        assert api_dict["cvssScore"] == 9.8
        assert api_dict["epssScore"] == 95.0
        assert api_dict["exploitationStatus"] == "ACTIVE"
        assert len(api_dict["references"]) == 1
        assert api_dict["vendors"] == ["vendor1"]
        assert api_dict["products"] == ["product1"]
        assert api_dict["tags"] == ["CWE-78", "RCE"]

    def test_ensure_output_directories(self, briefing_generator):
        """Test output directory creation."""
        # Remove directories if they exist
        if briefing_generator.posts_dir.exists():
            briefing_generator.posts_dir.rmdir()
        if briefing_generator.api_dir.exists():
            briefing_generator.api_dir.rmdir()

        # Ensure directories
        briefing_generator._ensure_output_directories()

        assert briefing_generator.posts_dir.exists()
        assert briefing_generator.api_dir.exists()

    def test_generate_briefing_with_risk_factors(
        self, briefing_generator, sample_vulnerabilities
    ):
        """Test briefing includes risk factors."""
        batch = VulnerabilityBatch(
            vulnerabilities=sample_vulnerabilities,
            metadata={},
            harvest_date=datetime.now(timezone.utc),
        )

        briefing_path = briefing_generator.generate_daily_briefing(batch)
        content = briefing_path.read_text()

        # Check risk factors are included
        assert "Risk Factors:" in content
        assert "CRITICAL severity" in content
        assert "Exploitation: ACTIVE" in content
        assert "HIGH severity" in content
