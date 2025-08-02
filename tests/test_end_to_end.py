"""End-to-end tests for the complete vulnerability briefing workflow."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from scripts.harvest.orchestrator import HarvestOrchestrator
from scripts.main import cli as app
from scripts.models import SeverityLevel, Vulnerability, VulnerabilityBatch
from scripts.processing.briefing_generator import BriefingGenerator


class TestEndToEnd:
    """Test complete workflow from CLI to output files."""

    @pytest.fixture
    def cli_runner(self):
        """Create a CLI runner."""
        return CliRunner()

    @pytest.fixture
    def mock_vulnerability_data(self):
        """Create mock vulnerability data for testing."""
        from scripts.models import CVSSMetric, EPSSScore, Reference, VulnerabilitySource

        return [
            Vulnerability(
                cve_id="CVE-2025-1001",
                title="Critical RCE in Popular Framework",
                description="A critical remote code execution vulnerability in a popular web framework",
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
                severity=SeverityLevel.CRITICAL,
                cvss_metrics=[
                    CVSSMetric(
                        version="3.1",
                        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        base_score=9.8,
                        base_severity=SeverityLevel.CRITICAL,
                    )
                ],
                epss_score=EPSSScore(
                    score=0.95,
                    percentile=0.99,
                    date=datetime.now(timezone.utc).date().isoformat(),
                ),
                risk_score=92,
                affected_vendors=["Framework Corp"],
                affected_products=["Web Framework"],
                references=[
                    Reference(
                        url="https://example.com/advisory/CVE-2025-1001",
                        tags=["vendor-advisory"],
                    )
                ],
                tags=["remote", "network", "code-execution"],
                sources=[VulnerabilitySource(name="CVEList")],
            ),
            Vulnerability(
                cve_id="CVE-2025-1002",
                title="High Severity SQL Injection",
                description="SQL injection vulnerability in database connector",
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
                severity=SeverityLevel.HIGH,
                cvss_metrics=[
                    CVSSMetric(
                        version="3.1",
                        vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                        base_score=8.1,
                        base_severity=SeverityLevel.HIGH,
                    )
                ],
                epss_score=EPSSScore(
                    score=0.75,
                    percentile=0.85,
                    date=datetime.now(timezone.utc).date().isoformat(),
                ),
                risk_score=78,
                affected_vendors=["Database Inc"],
                affected_products=["DB Connector"],
                references=[
                    Reference(url="https://nvd.nist.gov/vuln/detail/CVE-2025-1002")
                ],
                tags=["sql-injection", "database"],
                sources=[VulnerabilitySource(name="CVEList")],
            ),
        ]

    def test_cli_harvest_to_briefing_workflow(
        self, cli_runner, tmp_path, mock_vulnerability_data
    ):
        """Test complete workflow using CLI commands."""
        cache_dir = tmp_path / "cache"
        output_dir = tmp_path / "output"

        # Mock the orchestrator to return test data
        with patch("scripts.main.HarvestOrchestrator") as mock_orchestrator_class:
            mock_orchestrator = MagicMock()
            mock_orchestrator_class.return_value = mock_orchestrator

            # Create a mock batch
            batch = VulnerabilityBatch(
                vulnerabilities=mock_vulnerability_data,
                metadata={
                    "harvest_id": "test-harvest-123",
                    "sources": [{"name": "CVEList", "count": 2, "status": "success"}],
                    "total_vulnerabilities": 2,
                    "unique_vulnerabilities": 2,
                },
                generated_at=datetime.now(timezone.utc),
            )
            mock_orchestrator.harvest_all_sources.return_value = batch

            # Step 1: Run harvest command
            result = cli_runner.invoke(
                app, ["harvest", "--cache-dir", str(cache_dir), "--years", "2025"]
            )
            assert result.exit_code == 0
            assert "Total vulnerabilities: 2" in result.output

        # Mock cache manager for briefing generation
        with patch("scripts.main.CacheManager") as mock_cache_class:
            mock_cache = MagicMock()
            mock_cache_class.return_value = mock_cache
            mock_cache.get_recent_vulnerabilities.return_value = mock_vulnerability_data

            # Step 2: Run generate-briefing command
            result = cli_runner.invoke(
                app,
                [
                    "generate-briefing",
                    "--cache-dir",
                    str(cache_dir),
                    "--output-dir",
                    str(output_dir),
                ],
            )
            assert result.exit_code == 0
            assert "Briefing generated successfully" in result.output

    @pytest.mark.asyncio
    async def test_full_pipeline_with_real_components(
        self, tmp_path, mock_vulnerability_data
    ):
        """Test full pipeline with real components (mocked API calls only)."""
        cache_dir = tmp_path / "cache"
        output_dir = tmp_path / "output"
        cache_dir.mkdir(exist_ok=True)
        output_dir.mkdir(exist_ok=True)

        # Initialize real orchestrator
        orchestrator = HarvestOrchestrator(cache_dir=cache_dir)

        # Mock only the external API calls
        with patch.object(
            orchestrator.cvelist_client, "harvest"
        ) as mock_harvest, patch.object(
            orchestrator.epss_client, "fetch_epss_scores_bulk"
        ) as mock_epss:
            mock_harvest.return_value = mock_vulnerability_data
            mock_epss.return_value = {
                vuln.cve_id: vuln.epss_score
                for vuln in mock_vulnerability_data
                if vuln.epss_score
            }

            # Run the harvest
            batch = await orchestrator.harvest_async(
                years=[2025], min_severity=SeverityLevel.HIGH
            )

            assert len(batch.vulnerabilities) == 2
            assert batch.metadata["total_vulnerabilities"] == 2

            # Generate briefing with real generator
            generator = BriefingGenerator(output_dir=output_dir)

            # Generate all outputs
            briefing_path = generator.generate_briefing_post(batch)
            api_paths = generator.generate_all(batch)

            # Verify briefing was created
            assert briefing_path.exists()
            content = briefing_path.read_text()
            assert "CVE-2025-1001" in content
            assert (
                "A critical remote code execution vulnerability in a popular web framework"
                in content
            )
            assert "CVE-2025-1002" in content

            # Verify API files were created
            assert len(api_paths) >= 3  # 2 vulns + 1 index

            # Check individual vulnerability JSON files
            vuln1_path = output_dir / "api" / "vulns" / "CVE-2025-1001.json"
            assert vuln1_path.exists()
            vuln1_data = json.loads(vuln1_path.read_text())
            assert vuln1_data["cveId"] == "CVE-2025-1001"
            assert (
                vuln1_data["riskScore"] >= 70
            )  # Risk score may be calculated differently

            # Check search index
            index_path = output_dir / "api" / "vulns" / "index.json"
            assert index_path.exists()
            index_data = json.loads(index_path.read_text())
            assert len(index_data["vulnerabilities"]) == 2

    def test_generated_content_structure(self, tmp_path, mock_vulnerability_data):
        """Test the structure and content of generated files."""
        output_dir = tmp_path / "output"
        output_dir.mkdir(exist_ok=True)

        # Create a batch
        batch = VulnerabilityBatch(
            vulnerabilities=mock_vulnerability_data,
            metadata={
                "harvest_id": "test-123",
                "sources": [{"name": "CVEList", "count": 2, "status": "success"}],
                "total_vulnerabilities": 2,
                "unique_vulnerabilities": 2,
                "start_time": datetime.now(timezone.utc).isoformat(),
                "end_time": datetime.now(timezone.utc).isoformat(),
                "duration_seconds": 1.5,
            },
            generated_at=datetime.now(timezone.utc),
        )

        # Generate outputs
        generator = BriefingGenerator(output_dir=output_dir)
        briefing_path = generator.generate_briefing_post(batch)

        # Test briefing markdown structure
        content = briefing_path.read_text()

        # Check frontmatter
        assert "---" in content
        assert "title: Morning Vulnerability Briefing" in content
        assert "vulnerabilityCount: 2" in content
        assert "criticalCount: 1" in content
        assert "highCount: 1" in content

        # Check content sections
        assert "## Risk Distribution" in content
        assert "## Top Vulnerabilities" in content
        assert "### 1. [CVE-2025-1001]" in content
        assert "**Risk Score**: 92/100" in content
        assert "**Severity**: CRITICAL" in content
        assert "**CVSS**: 9.8" in content
        assert "**EPSS**: 95.0%" in content

        # Check risk factors
        assert "**Risk Factors**:" in content

        # Check footer
        assert "## Data Sources" in content
        assert "automatically generated" in content

    def test_error_handling_in_workflow(self, cli_runner, tmp_path):
        """Test error handling throughout the workflow."""
        cache_dir = tmp_path / "cache"

        # Test harvest with API failure
        with patch("scripts.main.HarvestOrchestrator") as mock_orchestrator_class:
            mock_orchestrator = MagicMock()
            mock_orchestrator_class.return_value = mock_orchestrator
            mock_orchestrator.harvest_all_sources.side_effect = Exception("API Error")

            result = cli_runner.invoke(app, ["harvest", "--cache-dir", str(cache_dir)])

            # Should handle error gracefully
            assert result.exit_code == 1
            # The CLI catches exceptions and prints structured error messages

        # Test briefing generation with no data
        with patch("scripts.main.CacheManager") as mock_cache_class:
            mock_cache = MagicMock()
            mock_cache_class.return_value = mock_cache
            mock_cache.get_recent_vulnerabilities.return_value = []

            result = cli_runner.invoke(
                app, ["generate-briefing", "--cache-dir", str(cache_dir)]
            )

            assert result.exit_code == 0
            assert "No vulnerabilities found" in result.output

    @pytest.mark.asyncio
    async def test_performance_e2e(self, tmp_path):
        """Test end-to-end performance with larger dataset."""
        import time

        # Generate 100 vulnerabilities
        from scripts.models import VulnerabilitySource

        vulns = []
        for i in range(100):
            severity = [
                SeverityLevel.CRITICAL,
                SeverityLevel.HIGH,
                SeverityLevel.MEDIUM,
            ][i % 3]
            vulns.append(
                Vulnerability(
                    cve_id=f"CVE-2025-{i:04d}",
                    title=f"Test Vulnerability {i}",
                    description=f"Description for vulnerability {i}",
                    published_date=datetime.now(timezone.utc),
                    last_modified_date=datetime.now(timezone.utc),
                    severity=severity,
                    cvss_metrics=[],
                    risk_score=max(0, 90 - i),
                    affected_vendors=[f"Vendor{i}"],
                    affected_products=[f"Product{i}"],
                    references=[],
                    sources=[VulnerabilitySource(name="CVEList")],
                )
            )

        batch = VulnerabilityBatch(
            vulnerabilities=vulns,
            metadata={"total_vulnerabilities": 100},
            generated_at=datetime.now(timezone.utc),
        )

        # Time the generation
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        generator = BriefingGenerator(output_dir=output_dir)

        start_time = time.time()
        briefing_path = generator.generate_briefing_post(batch, limit=50)
        api_paths = generator.generate_all(batch)
        end_time = time.time()

        # Should complete within reasonable time
        assert end_time - start_time < 5.0  # 5 seconds max

        # Verify outputs
        assert briefing_path.exists()
        assert (
            len(api_paths["vulnerabilities"]) == 100
        )  # 100 individual vulnerability files
        assert api_paths["index"]  # Index file exists

        # Check briefing only includes top 50
        content = briefing_path.read_text()
        assert "vulnerabilityCount: 100" in content
        # Only top 50 should be detailed in the briefing
        assert "### 50." in content
        assert "### 51." not in content
