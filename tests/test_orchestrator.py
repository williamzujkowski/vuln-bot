"""Tests for vulnerability pipeline orchestrator."""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timezone
from pathlib import Path

from scripts.orchestrator import VulnerabilityOrchestrator
from scripts.models import Vulnerability, SeverityLevel, VulnerabilityBatch


class TestVulnerabilityOrchestrator:
    """Test cases for VulnerabilityOrchestrator."""
    
    @pytest.fixture
    def orchestrator(self, tmp_path):
        """Create orchestrator instance."""
        with patch('scripts.orchestrator.CacheManager'):
            orch = VulnerabilityOrchestrator(
                cache_dir=tmp_path / "cache",
                output_dir=tmp_path / "output"
            )
            return orch
    
    @pytest.fixture
    def sample_vulnerabilities(self):
        """Create sample vulnerabilities."""
        return [
            Vulnerability(
                cve_id="CVE-2024-0001",
                title="Critical vulnerability",
                description="Critical RCE vulnerability",
                severity=SeverityLevel.CRITICAL,
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
            ),
            Vulnerability(
                cve_id="CVE-2024-0002",
                title="High vulnerability",
                description="High severity vulnerability",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
            ),
        ]
    
    @pytest.mark.asyncio
    async def test_run_pipeline_success(self, orchestrator, sample_vulnerabilities):
        """Test successful pipeline execution."""
        # Mock sources
        mock_source = AsyncMock()
        mock_source.fetch_recent.return_value = sample_vulnerabilities
        orchestrator.sources = {"test_source": mock_source}
        
        # Mock processors
        mock_processor = Mock()
        mock_processor.process.return_value = VulnerabilityBatch(
            vulnerabilities=sample_vulnerabilities,
            metadata={"processed": True}
        )
        orchestrator.processors = [mock_processor]
        
        # Run pipeline
        result = await orchestrator.run_pipeline()
        
        assert result is not None
        assert len(result.vulnerabilities) == 2
        assert mock_source.fetch_recent.called
        assert mock_processor.process.called
    
    @pytest.mark.asyncio
    async def test_run_pipeline_with_cache(self, orchestrator):
        """Test pipeline with cached data."""
        # Mock cache hit
        cached_data = VulnerabilityBatch(
            vulnerabilities=[
                Vulnerability(
                    cve_id="CVE-2024-0001",
                    title="Cached vulnerability",
                    description="From cache",
                    severity=SeverityLevel.HIGH,
                    published_date=datetime.now(timezone.utc),
                    last_modified_date=datetime.now(timezone.utc),
                )
            ],
            metadata={"cached": True}
        )
        
        orchestrator.cache_manager.get.return_value = cached_data.dict()
        
        result = await orchestrator.run_pipeline(use_cache=True)
        
        assert result is not None
        assert len(result.vulnerabilities) == 1
        assert result.vulnerabilities[0].title == "Cached vulnerability"
    
    @pytest.mark.asyncio
    async def test_fetch_from_sources_error_handling(self, orchestrator):
        """Test error handling in source fetching."""
        # Mock source with error
        mock_source = AsyncMock()
        mock_source.fetch_recent.side_effect = Exception("Source error")
        orchestrator.sources = {"failing_source": mock_source}
        
        vulns = await orchestrator._fetch_from_sources(days=7)
        
        # Should return empty list on error
        assert vulns == []
    
    def test_filter_vulnerabilities(self, orchestrator, sample_vulnerabilities):
        """Test vulnerability filtering."""
        # Add a medium severity vuln
        sample_vulnerabilities.append(
            Vulnerability(
                cve_id="CVE-2024-0003",
                title="Medium vulnerability",
                description="Medium severity",
                severity=SeverityLevel.MEDIUM,
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
            )
        )
        
        # Filter for HIGH and CRITICAL only
        filtered = orchestrator._filter_vulnerabilities(
            sample_vulnerabilities,
            min_severity=SeverityLevel.HIGH
        )
        
        assert len(filtered) == 2
        assert all(v.severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL] for v in filtered)
    
    def test_deduplicate_vulnerabilities(self, orchestrator):
        """Test vulnerability deduplication."""
        # Create duplicates
        vulns = [
            Vulnerability(
                cve_id="CVE-2024-0001",
                title="First version",
                description="Description 1",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
            ),
            Vulnerability(
                cve_id="CVE-2024-0001",  # Duplicate
                title="Second version",
                description="Description 2",
                severity=SeverityLevel.HIGH,
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
            ),
            Vulnerability(
                cve_id="CVE-2024-0002",
                title="Different CVE",
                description="Description",
                severity=SeverityLevel.CRITICAL,
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
            ),
        ]
        
        deduped = orchestrator._deduplicate_vulnerabilities(vulns)
        
        assert len(deduped) == 2
        cve_ids = [v.cve_id for v in deduped]
        assert "CVE-2024-0001" in cve_ids
        assert "CVE-2024-0002" in cve_ids
    
    def test_save_output(self, orchestrator, tmp_path, sample_vulnerabilities):
        """Test output saving."""
        batch = VulnerabilityBatch(
            vulnerabilities=sample_vulnerabilities,
            metadata={"test": True}
        )
        
        # Save output
        orchestrator.save_output(batch, format="json")
        
        # Check files were created
        output_files = list((tmp_path / "output").glob("*.json"))
        assert len(output_files) > 0
        
        # Verify content
        import json
        with open(output_files[0]) as f:
            data = json.load(f)
            assert "vulnerabilities" in data
            assert len(data["vulnerabilities"]) == 2
    
    @pytest.mark.asyncio
    async def test_concurrent_source_fetching(self, orchestrator):
        """Test concurrent fetching from multiple sources."""
        # Create multiple mock sources
        sources = {}
        for i in range(3):
            mock_source = AsyncMock()
            mock_source.fetch_recent.return_value = [
                Vulnerability(
                    cve_id=f"CVE-2024-{i:04d}",
                    title=f"Vuln from source {i}",
                    description=f"Description {i}",
                    severity=SeverityLevel.HIGH,
                    published_date=datetime.now(timezone.utc),
                    last_modified_date=datetime.now(timezone.utc),
                )
            ]
            sources[f"source_{i}"] = mock_source
        
        orchestrator.sources = sources
        
        vulns = await orchestrator._fetch_from_sources(days=7)
        
        # Should have vulnerabilities from all sources
        assert len(vulns) == 3
        assert all(f"CVE-2024-{i:04d}" in [v.cve_id for v in vulns] for i in range(3))
    
    def test_metrics_collection(self, orchestrator, sample_vulnerabilities):
        """Test metrics collection during pipeline."""
        batch = VulnerabilityBatch(
            vulnerabilities=sample_vulnerabilities,
            metadata={
                "source_counts": {"github": 1, "nvd": 1},
                "severity_counts": {"CRITICAL": 1, "HIGH": 1},
                "processing_time": 1.5
            }
        )
        
        metrics = orchestrator._collect_metrics(batch)
        
        assert metrics["total_vulnerabilities"] == 2
        assert metrics["severity_distribution"]["CRITICAL"] == 1
        assert metrics["severity_distribution"]["HIGH"] == 1
        assert "processing_time" in metrics