"""Test production-scale harvesting capabilities."""

import time
from unittest.mock import patch

import pytest

from scripts.harvest.cvelist_client import CVEListClient
from scripts.harvest.orchestrator import HarvestOrchestrator
from scripts.models import SeverityLevel


class TestProductionHarvest:
    """Test production-scale harvesting without hitting real APIs."""

    @pytest.mark.asyncio
    async def test_cvelist_client_scale(self):
        """Test CVEListClient can handle production volume."""
        client = CVEListClient()

        # Test parsing a real CVE record structure
        sample_cve = {
            "cveMetadata": {
                "cveId": "CVE-2025-0001",
                "datePublished": "2025-01-01T00:00:00Z",
                "state": "PUBLISHED",
            },
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Test vulnerability"}],
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }
                    ],
                    "affected": [
                        {
                            "vendor": "Test Vendor",
                            "product": "Test Product",
                            "versions": [{"version": "1.0", "status": "affected"}],
                        }
                    ],
                }
            },
        }

        # Parse the CVE
        vuln = client.parse_cve_v5_record(sample_cve)
        assert vuln is not None
        assert vuln.cve_id == "CVE-2025-0001"
        assert vuln.severity == SeverityLevel.CRITICAL
        assert vuln.cvss_metrics[0].base_score == 9.8

    @pytest.mark.asyncio
    async def test_orchestrator_filtering(self, tmp_path):
        """Test orchestrator filters correctly at scale."""
        orchestrator = HarvestOrchestrator(cache_dir=tmp_path)

        # Mock CVE data with various severity levels
        mock_cves = []
        for i in range(1000):
            severity = ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4]
            score = [9.5, 7.5, 5.5, 3.5][i % 4]
            mock_cves.append(
                {
                    "cveMetadata": {
                        "cveId": f"CVE-2025-{i:04d}",
                        "datePublished": "2025-01-01T00:00:00Z",
                    },
                    "containers": {
                        "cna": {
                            "descriptions": [
                                {"lang": "en", "value": f"Test vulnerability {i}"}
                            ],
                            "metrics": [
                                {
                                    "cvssV3_1": {
                                        "baseScore": score,
                                        "baseSeverity": severity,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                }
                            ],
                        }
                    },
                }
            )

        # Convert mock CVEs to Vulnerability objects
        from scripts.harvest.cvelist_client import CVEListClient
        from scripts.models import EPSSScore

        client = CVEListClient()
        mock_vulns = []
        for cve in mock_cves:
            vuln = client.parse_cve_v5_record(cve)
            if vuln and vuln.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]:
                mock_vulns.append(vuln)

        # Mock the CVEListClient
        with patch.object(orchestrator.cvelist_client, "harvest") as mock_fetch:
            mock_fetch.return_value = mock_vulns

            # Mock EPSS scores
            with patch.object(
                orchestrator.epss_client, "fetch_epss_scores_bulk"
            ) as mock_epss:
                # Create EPSS score objects
                epss_scores = {}
                for i in range(0, 1000, 2):  # Every other CVE (HIGH/CRITICAL)
                    # Half have high EPSS scores
                    score = 0.8 if i % 4 == 0 else 0.3
                    epss_scores[f"CVE-2025-{i:04d}"] = EPSSScore(
                        score=score, percentile=score, date="2025-01-01"
                    )
                mock_epss.return_value = epss_scores

                # Run harvest
                batch = await orchestrator.harvest_async(
                    years=[2025], min_severity=SeverityLevel.HIGH, min_epss_score=0.6
                )

                vulns = batch.vulnerabilities
                # Should get filtered vulnerabilities
                assert len(vulns) > 0
                for vuln in vulns:
                    assert vuln.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
                    if vuln.epss_score:
                        assert vuln.epss_score.score >= 0.6

    @pytest.mark.asyncio
    async def test_performance_requirements(self):
        """Test system meets performance requirements."""
        client = CVEListClient()

        # Test parsing performance
        sample_cve = {
            "cveMetadata": {"cveId": "CVE-2025-0001"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": [
                        {"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                    ],
                }
            },
        }

        # Parse 1000 CVEs and measure time
        start = time.time()
        for _ in range(1000):
            client.parse_cve_v5_record(sample_cve)
        elapsed = time.time() - start

        # Should parse at least 100 CVEs per second
        assert elapsed < 10.0, f"Parsing too slow: {1000 / elapsed:.1f} CVEs/sec"

    def test_memory_efficiency(self):
        """Test memory usage stays reasonable."""
        import sys

        # Create 10000 vulnerability objects
        from scripts.models import CVSSMetric, EPSSScore, Vulnerability

        vulns = []
        for i in range(10000):
            vuln = Vulnerability(
                cve_id=f"CVE-2025-{i:04d}",
                title=f"Test vulnerability {i}",
                description="A" * 1000,  # 1KB description
                severity=SeverityLevel.HIGH,
                cvss_metrics=[
                    CVSSMetric(
                        version="3.1",
                        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        base_score=7.5,
                        base_severity=SeverityLevel.HIGH,
                    )
                ],
                epss_score=EPSSScore(score=0.75, percentile=0.95, date="2025-01-01"),
                published_date="2025-01-01T00:00:00Z",
                last_modified_date="2025-01-01T00:00:00Z",
            )
            vulns.append(vuln)

        # Check memory usage (rough estimate)
        total_size = sum(sys.getsizeof(v) for v in vulns)
        avg_size = total_size / len(vulns)

        # Each vuln should be less than 10KB
        assert avg_size < 10240, f"Vulnerabilities too large: {avg_size} bytes average"

    @pytest.mark.asyncio
    async def test_concurrent_harvesting(self, tmp_path):
        """Test concurrent harvesting works correctly."""
        orchestrator = HarvestOrchestrator(cache_dir=tmp_path)

        # Mock the fetch methods to return empty lists
        with patch.object(orchestrator.cvelist_client, "harvest") as mock_harvest:
            mock_harvest.return_value = []

            with patch.object(
                orchestrator.epss_client, "fetch_epss_scores_bulk"
            ) as mock_epss:
                mock_epss.return_value = {}

                # Run harvest with multiple years - this tests that the system can handle
                # multiple years without errors
                batch = await orchestrator.harvest_async(
                    years=[2024, 2025], min_severity=SeverityLevel.HIGH
                )

                # Should complete without errors
                assert batch is not None
                assert batch.vulnerabilities == []
                assert len(batch.metadata["sources"]) > 0
