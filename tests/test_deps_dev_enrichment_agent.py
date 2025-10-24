"""Tests for DepsDevEnrichmentAgent."""

from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from scripts.agents.deps_dev_enrichment_agent import DepsDevEnrichmentAgent


class TestDepsDevEnrichmentAgentInitialization:
    """Test suite for DepsDevEnrichmentAgent initialization."""

    def test_initialization(self, tmp_path):
        """Test agent initialization."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)

        assert agent.name == "DepsDevEnrichmentAgent"
        assert agent.cache_dir == tmp_path
        assert len(agent.ecosystem_mappings) == 14
        assert agent.ecosystem_mappings["npm"] == "npm"
        assert agent.ecosystem_mappings["pypi"] == "pypi"
        assert agent.ecosystem_mappings["golang"] == "go"

    def test_initialization_without_cache(self):
        """Test initialization without cache directory."""
        agent = DepsDevEnrichmentAgent()

        assert agent.name == "DepsDevEnrichmentAgent"
        # BaseAgent sets default cache_dir to .cache/agents if None provided
        assert agent.cache_dir == Path(".cache/agents")

    def test_get_dependencies(self, tmp_path):
        """Test get_dependencies returns empty list."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        deps = agent.get_dependencies()

        assert deps == []


class TestPackageExtractionFromAffected:
    """Test suite for package extraction from affected items."""

    def test_extract_from_affected_item_basic(self, tmp_path):
        """Test extracting package from basic affected item."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "express"},
                    "versions": ["4.0.0", "4.1.0"],
                }
            ]
        }

        packages = agent.extract_package_info(vulnerability)

        assert len(packages) == 1
        assert packages[0]["ecosystem"] == "npm"
        assert packages[0]["name"] == "express"
        assert packages[0]["versions"] == ["4.0.0", "4.1.0"]

    def test_extract_from_affected_item_with_ranges(self, tmp_path):
        """Test extracting versions from ranges."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "affected": [
                {
                    "package": {"ecosystem": "pypi", "name": "django"},
                    "ranges": [
                        {
                            "events": [
                                {"introduced": "3.0.0"},
                                {"fixed": "3.2.0"},
                            ]
                        }
                    ],
                }
            ]
        }

        packages = agent.extract_package_info(vulnerability)

        assert len(packages) == 1
        assert packages[0]["ecosystem"] == "pypi"
        assert packages[0]["name"] == "django"
        assert ">=3.0.0" in packages[0]["versions"]
        assert "<3.2.0" in packages[0]["versions"]

    def test_extract_with_ecosystem_mapping(self, tmp_path):
        """Test ecosystem mapping (pip -> pypi)."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "affected": [{"package": {"ecosystem": "pip", "name": "requests"}}]
        }

        packages = agent.extract_package_info(vulnerability)

        assert len(packages) == 1
        assert packages[0]["ecosystem"] == "pypi"  # Mapped from pip
        assert packages[0]["name"] == "requests"


class TestPackageExtractionFromVendorProduct:
    """Test suite for package inference from vendor/product."""

    def test_infer_known_npm_package(self, tmp_path):
        """Test inferring known NPM package from vendor/product."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "vendors": ["facebook"],
            "products": ["react"],
        }

        packages = agent.extract_package_info(vulnerability)

        assert len(packages) == 1
        assert packages[0]["ecosystem"] == "npm"
        assert packages[0]["name"] == "react"

    def test_infer_known_pypi_package(self, tmp_path):
        """Test inferring known PyPI package."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "vendors": ["django"],
            "products": ["django"],
        }

        packages = agent.extract_package_info(vulnerability)

        assert len(packages) == 1
        assert packages[0]["ecosystem"] == "pypi"
        assert packages[0]["name"] == "django"

    def test_infer_scoped_npm_package(self, tmp_path):
        """Test inferring scoped NPM package from product name."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "vendors": ["company"],
            "products": ["@angular/core"],
        }

        packages = agent.extract_package_info(vulnerability)

        # Should infer as npm due to @ symbol
        assert any(p["name"] == "@angular/core" for p in packages)


class TestPackageExtractionFromText:
    """Test suite for package extraction from text descriptions."""

    def test_extract_npm_package_from_description(self, tmp_path):
        """Test extracting NPM package from description."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "description": "Vulnerability in npm package `express` version 4.x"
        }

        packages = agent.extract_package_info(vulnerability)

        npm_packages = [p for p in packages if p["ecosystem"] == "npm"]
        assert any(p["name"] == "express" for p in npm_packages)

    def test_extract_scoped_npm_package(self, tmp_path):
        """Test extracting scoped NPM package."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "description": "Affects @angular/core and @vue/compiler packages"
        }

        packages = agent.extract_package_info(vulnerability)

        npm_packages = [p for p in packages if p["ecosystem"] == "npm"]
        assert any("@angular/core" in p["name"] for p in npm_packages)
        assert any("@vue/compiler" in p["name"] for p in npm_packages)

    def test_extract_pypi_package_from_description(self, tmp_path):
        """Test extracting PyPI package from pip install command."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {"description": "Install with: pip install django==3.2.0"}

        packages = agent.extract_package_info(vulnerability)

        pypi_packages = [p for p in packages if p["ecosystem"] == "pypi"]
        assert any(p["name"] == "django" for p in pypi_packages)

    def test_extract_maven_package(self, tmp_path):
        """Test extracting Maven package from coordinates."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {"description": "Affects org.springframework:spring-core:5.3.0"}

        packages = agent.extract_package_info(vulnerability)

        maven_packages = [p for p in packages if p["ecosystem"] == "maven"]
        assert any(
            "org.springframework:spring-core" in p["name"] for p in maven_packages
        )


class TestPackageExtractionFromURLs:
    """Test suite for package extraction from reference URLs."""

    def test_extract_from_npm_url(self, tmp_path):
        """Test extracting package from NPM registry URL."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "references": [{"url": "https://www.npmjs.com/package/express"}]
        }

        packages = agent.extract_package_info(vulnerability)

        npm_packages = [p for p in packages if p["ecosystem"] == "npm"]
        assert any(p["name"] == "express" for p in npm_packages)

    def test_extract_from_pypi_url(self, tmp_path):
        """Test extracting package from PyPI URL."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {"references": [{"url": "https://pypi.org/project/requests"}]}

        packages = agent.extract_package_info(vulnerability)

        pypi_packages = [p for p in packages if p["ecosystem"] == "pypi"]
        assert any(p["name"] == "requests" for p in pypi_packages)

    def test_extract_from_rubygems_url(self, tmp_path):
        """Test extracting package from RubyGems URL."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {"references": [{"url": "https://rubygems.org/gems/rails"}]}

        packages = agent.extract_package_info(vulnerability)

        rubygems_packages = [p for p in packages if p["ecosystem"] == "rubygems"]
        assert any(p["name"] == "rails" for p in rubygems_packages)

    def test_extract_from_maven_url(self, tmp_path):
        """Test extracting package from Maven repository URL."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "references": [
                {
                    "url": "https://mvnrepository.com/artifact/org.springframework/spring-core"
                }
            ]
        }

        packages = agent.extract_package_info(vulnerability)

        maven_packages = [p for p in packages if p["ecosystem"] == "maven"]
        assert any(
            "org.springframework:spring-core" in p["name"] for p in maven_packages
        )

    def test_extract_from_packagist_url(self, tmp_path):
        """Test extracting package from Packagist URL."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "references": [{"url": "https://packagist.org/packages/symfony/symfony"}]
        }

        packages = agent.extract_package_info(vulnerability)

        packagist_packages = [p for p in packages if p["ecosystem"] == "packagist"]
        assert any(p["name"] == "symfony/symfony" for p in packagist_packages)


class TestPackageDeduplication:
    """Test suite for package deduplication."""

    def test_deduplicate_packages(self, tmp_path):
        """Test that duplicate packages are removed."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "description": "npm package express is vulnerable",
            "references": [{"url": "https://www.npmjs.com/package/express"}],
        }

        packages = agent.extract_package_info(vulnerability)

        # Should only have 1 express package despite 2 sources
        express_packages = [p for p in packages if p["name"] == "express"]
        assert len(express_packages) == 1


class TestDepsDevLinkGeneration:
    """Test suite for deps.dev link generation."""

    def test_generate_basic_link(self, tmp_path):
        """Test generating basic deps.dev link."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        packages = [{"ecosystem": "npm", "name": "express", "versions": []}]

        links = agent.generate_deps_dev_links(packages)

        assert len(links) == 1
        assert links[0]["ecosystem"] == "npm"
        assert links[0]["package"] == "express"
        assert links[0]["url"] == "https://deps.dev/npm/express"
        assert "View express on deps.dev" in links[0]["title"]
        assert links[0]["type"] == "package_impact"

    def test_generate_link_with_version(self, tmp_path):
        """Test generating deps.dev link with specific version."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        packages = [{"ecosystem": "pypi", "name": "django", "versions": ["3.2.0"]}]

        links = agent.generate_deps_dev_links(packages)

        assert len(links) == 1
        assert links[0]["url"] == "https://deps.dev/pypi/django/3.2.0"
        assert "View django@3.2.0 on deps.dev" in links[0]["title"]
        assert links[0]["version"] == "3.2.0"

    def test_generate_link_with_version_operators(self, tmp_path):
        """Test version operator cleanup in URLs."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        packages = [{"ecosystem": "npm", "name": "react", "versions": [">=17.0.0"]}]

        links = agent.generate_deps_dev_links(packages)

        assert len(links) == 1
        # Version operators should be stripped
        assert links[0]["url"] == "https://deps.dev/npm/react/17.0.0"
        assert links[0]["version"] == "17.0.0"

    def test_generate_links_for_multiple_packages(self, tmp_path):
        """Test generating links for multiple packages."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        packages = [
            {"ecosystem": "npm", "name": "express", "versions": []},
            {"ecosystem": "pypi", "name": "django", "versions": []},
        ]

        links = agent.generate_deps_dev_links(packages)

        assert len(links) == 2
        assert any(link["package"] == "express" for link in links)
        assert any(link["package"] == "django" for link in links)


class TestVulnerabilityEnrichment:
    """Test suite for vulnerability enrichment."""

    def test_enrich_vulnerability_with_packages(self, tmp_path):
        """Test enriching vulnerability with package data."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability: Dict[str, Any] = {
            "cve_id": "CVE-2024-0001",
            "affected": [{"package": {"ecosystem": "npm", "name": "express"}}],
        }

        with patch.object(agent, "logger"):
            enriched = agent.enrich_vulnerability(vulnerability)

        assert "enrichments" in enriched
        assert "deps_dev" in enriched["enrichments"]
        assert len(enriched["enrichments"]["deps_dev"]["packages"]) == 1
        assert len(enriched["enrichments"]["deps_dev"]["links"]) == 1

        # Check references were added
        assert "references" in enriched
        deps_refs = [r for r in enriched["references"] if r["source"] == "deps.dev"]
        assert len(deps_refs) == 1
        assert deps_refs[0]["type"] == "Package Impact Analysis"
        assert "package" in deps_refs[0]["tags"]

    def test_enrich_vulnerability_no_packages(self, tmp_path):
        """Test enriching vulnerability with no package data."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability: Dict[str, Any] = {
            "cve_id": "CVE-2024-0002",
            "description": "Generic vulnerability with no package references",
        }

        with patch.object(agent, "logger"):
            enriched = agent.enrich_vulnerability(vulnerability)

        # Should not add deps_dev enrichment if no packages found
        assert "deps_dev" not in enriched.get("enrichments", {})

    def test_enrich_preserves_existing_enrichments(self, tmp_path):
        """Test that enrichment preserves existing data."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability: Dict[str, Any] = {
            "cve_id": "CVE-2024-0003",
            "enrichments": {"existing": "data"},
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}}],
        }

        with patch.object(agent, "logger"):
            enriched = agent.enrich_vulnerability(vulnerability)

        assert "existing" in enriched["enrichments"]
        assert enriched["enrichments"]["existing"] == "data"
        assert "deps_dev" in enriched["enrichments"]


class TestBatchEnrichment:
    """Test suite for batch enrichment."""

    def test_enrich_batch_success(self, tmp_path):
        """Test batch enrichment of multiple vulnerabilities."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerabilities = [
            {
                "cve_id": "CVE-2024-0001",
                "affected": [{"package": {"ecosystem": "npm", "name": "express"}}],
            },
            {
                "cve_id": "CVE-2024-0002",
                "affected": [{"package": {"ecosystem": "pypi", "name": "django"}}],
            },
            {"cve_id": "CVE-2024-0003", "description": "No packages"},
        ]

        with patch.object(agent, "logger"):
            enriched = agent.enrich_batch(vulnerabilities)

        assert len(enriched) == 3
        # First two should have deps_dev enrichment
        assert "deps_dev" in enriched[0].get("enrichments", {})
        assert "deps_dev" in enriched[1].get("enrichments", {})
        # Third should not
        assert "deps_dev" not in enriched[2].get("enrichments", {})

    def test_enrich_batch_empty(self, tmp_path):
        """Test batch enrichment with empty list."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)

        with patch.object(agent, "logger"):
            enriched = agent.enrich_batch([])

        assert len(enriched) == 0

    def test_enrich_batch_preserves_originals(self, tmp_path):
        """Test that batch enrichment doesn't mutate original data."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        original = {
            "cve_id": "CVE-2024-0001",
            "affected": [{"package": {"ecosystem": "npm", "name": "express"}}],
        }

        with patch.object(agent, "logger"):
            enriched = agent.enrich_batch([original])

        # Original should not have enrichments
        assert "enrichments" not in original
        # Enriched should have enrichments
        assert "enrichments" in enriched[0]


class TestAsyncExecution:
    """Test suite for async execution."""

    @pytest.mark.asyncio
    async def test_execute_async_success(self, tmp_path):
        """Test async execute method with valid data."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        task = {
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-0001",
                    "affected": [{"package": {"ecosystem": "npm", "name": "express"}}],
                },
                {
                    "cve_id": "CVE-2024-0002",
                    "affected": [{"package": {"ecosystem": "pypi", "name": "django"}}],
                },
            ]
        }

        with patch.object(agent, "logger"):
            result = await agent.execute(task)

        assert result["success"] is True
        assert len(result["vulnerabilities"]) == 2
        assert result["statistics"]["total_vulnerabilities"] == 2
        assert result["statistics"]["enriched_with_deps_dev"] == 2
        assert result["statistics"]["total_packages_found"] == 2
        assert result["statistics"]["enrichment_rate"] == 100.0

    @pytest.mark.asyncio
    async def test_execute_async_no_vulnerabilities(self, tmp_path):
        """Test async execute with no vulnerabilities."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        task = {}

        result = await agent.execute(task)

        assert result["success"] is False
        assert "error" in result
        assert result["error"] == "No vulnerabilities provided"

    @pytest.mark.asyncio
    async def test_execute_async_statistics_calculation(self, tmp_path):
        """Test statistics calculation in async execute."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        task = {
            "vulnerabilities": [
                {
                    "cve_id": "CVE-2024-0001",
                    "affected": [
                        {"package": {"ecosystem": "npm", "name": "express"}},
                        {"package": {"ecosystem": "npm", "name": "lodash"}},
                    ],
                },
                {"cve_id": "CVE-2024-0002", "description": "No packages"},
            ]
        }

        with patch.object(agent, "logger"):
            result = await agent.execute(task)

        assert result["success"] is True
        assert result["statistics"]["total_vulnerabilities"] == 2
        assert result["statistics"]["enriched_with_deps_dev"] == 1
        assert result["statistics"]["total_packages_found"] == 2
        assert result["statistics"]["enrichment_rate"] == 50.0


class TestEdgeCases:
    """Test suite for edge cases."""

    def test_extract_from_malformed_affected(self, tmp_path):
        """Test handling malformed affected items."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {
            "affected": [
                "string instead of dict",
                {"package": None},
                {"package": {"ecosystem": "npm"}},  # Missing name
                {"package": {"name": "express"}},  # Missing ecosystem
            ]
        }

        packages = agent.extract_package_info(vulnerability)

        # Should handle errors gracefully
        assert isinstance(packages, list)

    def test_extract_from_empty_references(self, tmp_path):
        """Test handling empty references list."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        vulnerability = {"references": []}

        packages = agent.extract_package_info(vulnerability)

        assert packages == []

    def test_generate_links_with_empty_ecosystem(self, tmp_path):
        """Test link generation skips packages without ecosystem."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        packages = [
            {"ecosystem": "", "name": "express", "versions": []},
            {"ecosystem": "npm", "name": "", "versions": []},
        ]

        links = agent.generate_deps_dev_links(packages)

        # Should skip both invalid packages
        assert len(links) == 0

    def test_url_encoding_in_package_names(self, tmp_path):
        """Test URL encoding for special characters in package names."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        packages = [{"ecosystem": "npm", "name": "@scope/package", "versions": []}]

        links = agent.generate_deps_dev_links(packages)

        # Special characters are URL encoded (quote with safe='')
        assert links[0]["url"] == "https://deps.dev/npm/%40scope%2Fpackage"

    def test_multiple_versions_skips_version_in_url(self, tmp_path):
        """Test that version is skipped when multiple versions exist."""
        agent = DepsDevEnrichmentAgent(cache_dir=tmp_path)
        packages = [
            {
                "ecosystem": "npm",
                "name": "express",
                "versions": ["4.0.0", "4.1.0", "4.2.0"],
            }
        ]

        links = agent.generate_deps_dev_links(packages)

        # With multiple versions, URL should not include version (only when len==1)
        assert links[0]["url"] == "https://deps.dev/npm/express"
        assert "version" not in links[0]
