"""Tests for static page agent module."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from scripts.agents.static_page_agent import StaticPageAgent
from scripts.models import CVSSMetric, SeverityLevel, Vulnerability


class TestStaticPageAgent:
    """Test cases for StaticPageAgent."""

    @pytest.fixture
    def agent(self, tmp_path):
        """Create static page agent instance."""
        return StaticPageAgent(
            output_dir=tmp_path / "output",
            template_dir=tmp_path / "templates"
        )

    @pytest.fixture
    def sample_vulnerability(self):
        """Create sample vulnerability."""
        return Vulnerability(
            cve_id="CVE-2024-1234",
            title="CVE-2024-1234: Test vulnerability",
            description="A test vulnerability for unit testing",
            severity=SeverityLevel.HIGH,
            published_date=datetime.now(timezone.utc),
            last_modified_date=datetime.now(timezone.utc),
            cvss_metrics=[
                CVSSMetric(
                    version="3.1",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    base_score=9.8,
                    base_severity=SeverityLevel.CRITICAL,
                )
            ],
            affected_vendors=["TestVendor"],
            affected_products=["TestProduct"],
            tags=["test", "vulnerability"],
        )

    def test_initialization(self, agent, tmp_path):
        """Test agent initialization."""
        assert agent.output_dir == tmp_path / "output"
        assert agent.template_dir == tmp_path / "templates"
        assert agent.output_dir.exists()

    def test_generate_cve_page(self, agent, sample_vulnerability, tmp_path):
        """Test CVE page generation."""
        # Create a simple template
        template_content = """---
layout: cve-detail
cve_id: {{ cve_id }}
title: {{ title }}
severity: {{ severity }}
---

{{ description }}
"""
        template_path = tmp_path / "templates" / "cve-detail.md"
        template_path.parent.mkdir(exist_ok=True)
        template_path.write_text(template_content)

        # Generate page
        output_path = agent.generate_cve_page(sample_vulnerability)

        assert output_path is not None
        assert output_path.exists()
        assert output_path.name == "CVE-2024-1234.md"

        # Check content
        content = output_path.read_text()
        assert "CVE-2024-1234" in content
        assert "Test vulnerability" in content
        assert "HIGH" in content

    def test_generate_index_page(self, agent, sample_vulnerability, tmp_path):
        """Test index page generation."""
        vulnerabilities = [sample_vulnerability]

        # Create index template
        template_content = """# Vulnerability Index

Total: {{ total_vulns }}

{% for vuln in vulnerabilities %}
- {{ vuln.cve_id }}: {{ vuln.title }}
{% endfor %}
"""
        template_path = tmp_path / "templates" / "index.md"
        template_path.parent.mkdir(exist_ok=True)
        template_path.write_text(template_content)

        # Generate index
        output_path = agent.generate_index_page(vulnerabilities)

        assert output_path is not None
        assert output_path.exists()

        # Check content
        content = output_path.read_text()
        assert "CVE-2024-1234" in content
        assert "Total: 1" in content

    def test_generate_json_api(self, agent, sample_vulnerability):
        """Test JSON API generation."""
        vulnerabilities = [sample_vulnerability]

        # Generate API files
        api_files = agent.generate_json_api(vulnerabilities)

        assert len(api_files) > 0

        # Check main index file
        index_file = next((f for f in api_files if f.name == "index.json"), None)
        assert index_file is not None
        assert index_file.exists()

        # Verify JSON content
        with open(index_file) as f:
            data = json.load(f)
            assert "vulnerabilities" in data
            assert len(data["vulnerabilities"]) == 1
            assert data["vulnerabilities"][0]["cveId"] == "CVE-2024-1234"

    def test_chunked_json_generation(self, agent):
        """Test chunked JSON generation for large datasets."""
        # Create many vulnerabilities
        vulnerabilities = []
        for i in range(100):
            vuln = Vulnerability(
                cve_id=f"CVE-2024-{i:04d}",
                title=f"Test vulnerability {i}",
                description=f"Description {i}",
                severity=SeverityLevel.HIGH if i % 2 == 0 else SeverityLevel.CRITICAL,
                published_date=datetime.now(timezone.utc),
                last_modified_date=datetime.now(timezone.utc),
            )
            vulnerabilities.append(vuln)

        # Generate chunked API
        api_files = agent.generate_json_api(vulnerabilities, chunk_size=25)

        # Should have multiple chunk files
        chunk_files = [f for f in api_files if "chunk" in f.name]
        assert len(chunk_files) > 1

        # Verify chunk index
        chunk_index = next((f for f in api_files if f.name == "chunk-index.json"), None)
        assert chunk_index is not None

    def test_template_rendering(self, agent):
        """Test Jinja2 template rendering."""
        template_str = "Hello {{ name }}! Count: {{ items|length }}"
        context = {"name": "Test", "items": [1, 2, 3]}

        rendered = agent._render_template(template_str, context)

        assert rendered == "Hello Test! Count: 3"

    def test_safe_filename_generation(self, agent):
        """Test safe filename generation."""
        # Normal CVE ID
        filename = agent._safe_filename("CVE-2024-1234")
        assert filename == "CVE-2024-1234"

        # With special characters
        filename = agent._safe_filename("CVE/2024\\1234:test")
        assert "/" not in filename
        assert "\\" not in filename
        assert ":" not in filename

    def test_error_handling(self, agent, sample_vulnerability):
        """Test error handling in page generation."""
        # Remove output directory to cause error
        agent.output_dir = Path("/invalid/path/that/does/not/exist")

        # Should handle gracefully
        output_path = agent.generate_cve_page(sample_vulnerability)
        assert output_path is None  # or handle according to implementation
