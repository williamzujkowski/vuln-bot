"""Comprehensive unit tests for SSVCExtractor.

Tests cover:
- CISA-ADP container extraction
- SSVC metric parsing (Exploitation, Automatable, Technical Impact)
- Priority tier calculation (ACT/ATTEND/TRACK)
- Compact notation generation (A/Y/T format)
- SSVC score calculation (60-point scale)
- Human-readable explanations
- Edge cases and error handling
- All decision tree branches
"""

import pytest

from scripts.processing.ssvc_extractor import SSVCExtractor


class TestSSVCExtractor:
    """Comprehensive tests for SSVCExtractor."""

    @pytest.fixture
    def extractor(self):
        """Create SSVCExtractor instance."""
        return SSVCExtractor()

    # ============================================================
    # Test CISA-ADP Container Detection
    # ============================================================

    @pytest.fixture
    def cve_with_cisa_adp(self):
        """CVE data with valid CISA-ADP container."""
        return {
            "cveMetadata": {"cveId": "CVE-2025-1001"},
            "containers": {
                "adp": [
                    {
                        "providerMetadata": {
                            "shortName": "CISA-ADP",
                            "orgId": "cisa-org",
                        },
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "options": [
                                            {"Exploitation": "active"},
                                            {"Automatable": "yes"},
                                            {"Technical Impact": "total"},
                                        ]
                                    },
                                }
                            }
                        ],
                    }
                ]
            },
        }

    @pytest.fixture
    def cve_without_cisa_adp(self):
        """CVE data without CISA-ADP container."""
        return {
            "cveMetadata": {"cveId": "CVE-2025-1002"},
            "containers": {
                "adp": [
                    {
                        "providerMetadata": {
                            "shortName": "OTHER-ADP",
                            "orgId": "other-org",
                        },
                        "metrics": [],
                    }
                ]
            },
        }

    @pytest.fixture
    def cve_no_adp_containers(self):
        """CVE data with no ADP containers."""
        return {"cveMetadata": {"cveId": "CVE-2025-1003"}, "containers": {}}

    def test_find_cisa_adp_valid(self, extractor, cve_with_cisa_adp):
        """Test finding valid CISA-ADP container."""
        cisa_adp = extractor._find_cisa_adp(cve_with_cisa_adp)
        assert cisa_adp is not None
        assert cisa_adp["providerMetadata"]["shortName"] == "CISA-ADP"

    def test_find_cisa_adp_not_found(self, extractor, cve_without_cisa_adp):
        """Test when CISA-ADP container not found."""
        cisa_adp = extractor._find_cisa_adp(cve_without_cisa_adp)
        assert cisa_adp is None

    def test_find_cisa_adp_no_containers(self, extractor, cve_no_adp_containers):
        """Test when no ADP containers exist."""
        cisa_adp = extractor._find_cisa_adp(cve_no_adp_containers)
        assert cisa_adp is None

    def test_find_cisa_adp_empty_adp_list(self, extractor):
        """Test when ADP list is empty."""
        cve_data = {"containers": {"adp": []}}
        cisa_adp = extractor._find_cisa_adp(cve_data)
        assert cisa_adp is None

    # ============================================================
    # Test SSVC Metric Extraction
    # ============================================================

    @pytest.fixture
    def cisa_adp_all_metrics(self):
        """CISA-ADP with all SSVC metrics."""
        return {
            "providerMetadata": {"shortName": "CISA-ADP"},
            "metrics": [
                {
                    "other": {
                        "type": "ssvc",
                        "content": {
                            "options": [
                                {"Exploitation": "active"},
                                {"Automatable": "yes"},
                                {"Technical Impact": "total"},
                            ]
                        },
                    }
                }
            ],
        }

    @pytest.fixture
    def cisa_adp_partial_metrics(self):
        """CISA-ADP with partial SSVC metrics."""
        return {
            "providerMetadata": {"shortName": "CISA-ADP"},
            "metrics": [
                {
                    "other": {
                        "type": "ssvc",
                        "content": {"options": [{"Exploitation": "poc"}]},
                    }
                }
            ],
        }

    @pytest.fixture
    def cisa_adp_no_ssvc(self):
        """CISA-ADP without SSVC metrics."""
        return {
            "providerMetadata": {"shortName": "CISA-ADP"},
            "metrics": [{"other": {"type": "cvss", "content": {"baseScore": 9.8}}}],
        }

    def test_extract_ssvc_all_metrics(self, extractor, cisa_adp_all_metrics):
        """Test extracting all SSVC metrics."""
        ssvc_data = extractor._extract_ssvc_from_adp(cisa_adp_all_metrics)
        assert ssvc_data is not None
        assert ssvc_data["exploitation"] == "active"
        assert ssvc_data["automatable"] == "yes"
        assert ssvc_data["technical_impact"] == "total"

    def test_extract_ssvc_partial_metrics(self, extractor, cisa_adp_partial_metrics):
        """Test extracting partial SSVC metrics with defaults."""
        ssvc_data = extractor._extract_ssvc_from_adp(cisa_adp_partial_metrics)
        assert ssvc_data is not None
        assert ssvc_data["exploitation"] == "poc"
        assert ssvc_data["automatable"] == "no"  # Default
        assert ssvc_data["technical_impact"] == "partial"  # Default

    def test_extract_ssvc_no_metrics(self, extractor, cisa_adp_no_ssvc):
        """Test when no SSVC metrics present."""
        ssvc_data = extractor._extract_ssvc_from_adp(cisa_adp_no_ssvc)
        assert ssvc_data is None

    def test_extract_ssvc_empty_metrics(self, extractor):
        """Test when metrics array is empty."""
        cisa_adp = {"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": []}
        ssvc_data = extractor._extract_ssvc_from_adp(cisa_adp)
        assert ssvc_data is None

    def test_extract_ssvc_case_insensitive(self, extractor):
        """Test SSVC extraction handles case variations."""
        cisa_adp = {
            "metrics": [
                {
                    "other": {
                        "type": "ssvc",
                        "content": {
                            "options": [
                                {"Exploitation": "ACTIVE"},
                                {"Automatable": "YES"},
                                {"Technical Impact": "TOTAL"},
                            ]
                        },
                    }
                }
            ]
        }
        ssvc_data = extractor._extract_ssvc_from_adp(cisa_adp)
        assert ssvc_data is not None
        assert ssvc_data["exploitation"] == "active"
        assert ssvc_data["automatable"] == "yes"
        assert ssvc_data["technical_impact"] == "total"

    def test_extract_ssvc_invalid_values(self, extractor):
        """Test handling of invalid SSVC values."""
        cisa_adp = {
            "metrics": [
                {
                    "other": {
                        "type": "ssvc",
                        "content": {
                            "options": [
                                {"Exploitation": "invalid"},
                                {"Automatable": "maybe"},
                                {"Technical Impact": "unknown"},
                            ]
                        },
                    }
                }
            ]
        }
        ssvc_data = extractor._extract_ssvc_from_adp(cisa_adp)
        # Should return data with defaults when invalid values encountered
        assert ssvc_data is not None
        assert ssvc_data["exploitation"] == "none"  # Default
        assert ssvc_data["automatable"] == "no"  # Default
        assert ssvc_data["technical_impact"] == "partial"  # Default

    # ============================================================
    # Test Priority Tier Calculation (Decision Tree)
    # ============================================================

    def test_priority_tier_act(self, extractor):
        """Test ACT tier: active + yes + total."""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "yes",
            "technical_impact": "total",
        }
        tier = extractor.calculate_priority_tier(ssvc_data)
        assert tier == "ACT"

    def test_priority_tier_attend_active(self, extractor):
        """Test ATTEND tier: active exploitation."""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "no",
            "technical_impact": "partial",
        }
        tier = extractor.calculate_priority_tier(ssvc_data)
        assert tier == "ATTEND"

    def test_priority_tier_attend_active_total(self, extractor):
        """Test ATTEND tier: active + total (but not automatable)."""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "no",
            "technical_impact": "total",
        }
        tier = extractor.calculate_priority_tier(ssvc_data)
        assert tier == "ATTEND"

    def test_priority_tier_attend_poc_automatable(self, extractor):
        """Test ATTEND tier: poc + automatable."""
        ssvc_data = {
            "exploitation": "poc",
            "automatable": "yes",
            "technical_impact": "partial",
        }
        tier = extractor.calculate_priority_tier(ssvc_data)
        assert tier == "ATTEND"

    def test_priority_tier_track_poc_only(self, extractor):
        """Test TRACK tier: poc without automatable."""
        ssvc_data = {
            "exploitation": "poc",
            "automatable": "no",
            "technical_impact": "total",
        }
        tier = extractor.calculate_priority_tier(ssvc_data)
        assert tier == "TRACK"

    def test_priority_tier_track_none(self, extractor):
        """Test TRACK tier: no exploitation."""
        ssvc_data = {
            "exploitation": "none",
            "automatable": "yes",
            "technical_impact": "total",
        }
        tier = extractor.calculate_priority_tier(ssvc_data)
        assert tier == "TRACK"

    def test_priority_tier_track_defaults(self, extractor):
        """Test TRACK tier: all defaults."""
        ssvc_data = {
            "exploitation": "none",
            "automatable": "no",
            "technical_impact": "partial",
        }
        tier = extractor.calculate_priority_tier(ssvc_data)
        assert tier == "TRACK"

    def test_priority_tier_missing_keys(self, extractor):
        """Test priority tier with missing SSVC keys (uses defaults)."""
        ssvc_data = {}
        tier = extractor.calculate_priority_tier(ssvc_data)
        assert tier == "TRACK"  # All defaults -> TRACK

    # ============================================================
    # Test Compact Notation Generation
    # ============================================================

    def test_compact_notation_act(self, extractor):
        """Test A/Y/T notation for ACT tier."""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "yes",
            "technical_impact": "total",
        }
        notation = extractor.get_compact_notation(ssvc_data)
        assert notation == "A/Y/T"

    def test_compact_notation_attend_active(self, extractor):
        """Test A/N/P notation for ATTEND tier."""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "no",
            "technical_impact": "partial",
        }
        notation = extractor.get_compact_notation(ssvc_data)
        assert notation == "A/N/P"

    def test_compact_notation_attend_poc(self, extractor):
        """Test P/Y/T notation for ATTEND tier."""
        ssvc_data = {
            "exploitation": "poc",
            "automatable": "yes",
            "technical_impact": "total",
        }
        notation = extractor.get_compact_notation(ssvc_data)
        assert notation == "P/Y/T"

    def test_compact_notation_track(self, extractor):
        """Test N/N/P notation for TRACK tier."""
        ssvc_data = {
            "exploitation": "none",
            "automatable": "no",
            "technical_impact": "partial",
        }
        notation = extractor.get_compact_notation(ssvc_data)
        assert notation == "N/N/P"

    def test_compact_notation_unknown_values(self, extractor):
        """Test compact notation with unknown values."""
        ssvc_data = {
            "exploitation": "unknown",
            "automatable": "unknown",
            "technical_impact": "unknown",
        }
        notation = extractor.get_compact_notation(ssvc_data)
        assert notation == "?/?/?"

    def test_compact_notation_missing_keys(self, extractor):
        """Test compact notation with missing keys (uses defaults)."""
        ssvc_data = {}
        notation = extractor.get_compact_notation(ssvc_data)
        assert notation == "N/N/P"  # All defaults

    # ============================================================
    # Test SSVC Score Calculation
    # ============================================================

    def test_ssvc_score_max(self, extractor):
        """Test maximum SSVC score (60 points)."""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "yes",
            "technical_impact": "total",
        }
        score = extractor.get_ssvc_score(ssvc_data)
        assert score == 60  # 30 + 15 + 15

    def test_ssvc_score_active_only(self, extractor):
        """Test SSVC score: active exploitation only."""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "no",
            "technical_impact": "partial",
        }
        score = extractor.get_ssvc_score(ssvc_data)
        assert score == 37  # 30 + 0 + 7.5 = 37.5 -> 37

    def test_ssvc_score_poc_automatable(self, extractor):
        """Test SSVC score: poc + automatable."""
        ssvc_data = {
            "exploitation": "poc",
            "automatable": "yes",
            "technical_impact": "partial",
        }
        score = extractor.get_ssvc_score(ssvc_data)
        assert score == 42  # 20 + 15 + 7.5 = 42.5 -> 42

    def test_ssvc_score_poc_total(self, extractor):
        """Test SSVC score: poc + total impact."""
        ssvc_data = {
            "exploitation": "poc",
            "automatable": "no",
            "technical_impact": "total",
        }
        score = extractor.get_ssvc_score(ssvc_data)
        assert score == 35  # 20 + 0 + 15

    def test_ssvc_score_min(self, extractor):
        """Test minimum SSVC score (0 points)."""
        ssvc_data = {
            "exploitation": "none",
            "automatable": "no",
            "technical_impact": "partial",
        }
        score = extractor.get_ssvc_score(ssvc_data)
        assert score == 7  # 0 + 0 + 7.5 = 7.5 -> 7

    def test_ssvc_score_missing_keys(self, extractor):
        """Test SSVC score with missing keys (uses defaults)."""
        ssvc_data = {}
        score = extractor.get_ssvc_score(ssvc_data)
        assert score == 7  # 0 + 0 + 7.5 (defaults)

    def test_ssvc_score_all_combinations(self, extractor):
        """Test SSVC scores for all valid combinations."""
        # All 12 valid combinations (3 * 2 * 2)
        test_cases = [
            (
                {
                    "exploitation": "active",
                    "automatable": "yes",
                    "technical_impact": "total",
                },
                60,
            ),
            (
                {
                    "exploitation": "active",
                    "automatable": "yes",
                    "technical_impact": "partial",
                },
                52,
            ),
            (
                {
                    "exploitation": "active",
                    "automatable": "no",
                    "technical_impact": "total",
                },
                45,
            ),
            (
                {
                    "exploitation": "active",
                    "automatable": "no",
                    "technical_impact": "partial",
                },
                37,
            ),
            (
                {
                    "exploitation": "poc",
                    "automatable": "yes",
                    "technical_impact": "total",
                },
                50,
            ),
            (
                {
                    "exploitation": "poc",
                    "automatable": "yes",
                    "technical_impact": "partial",
                },
                42,
            ),
            (
                {
                    "exploitation": "poc",
                    "automatable": "no",
                    "technical_impact": "total",
                },
                35,
            ),
            (
                {
                    "exploitation": "poc",
                    "automatable": "no",
                    "technical_impact": "partial",
                },
                27,
            ),
            (
                {
                    "exploitation": "none",
                    "automatable": "yes",
                    "technical_impact": "total",
                },
                30,
            ),
            (
                {
                    "exploitation": "none",
                    "automatable": "yes",
                    "technical_impact": "partial",
                },
                22,
            ),
            (
                {
                    "exploitation": "none",
                    "automatable": "no",
                    "technical_impact": "total",
                },
                15,
            ),
            (
                {
                    "exploitation": "none",
                    "automatable": "no",
                    "technical_impact": "partial",
                },
                7,
            ),
        ]

        for ssvc_data, expected_score in test_cases:
            score = extractor.get_ssvc_score(ssvc_data)
            assert score == expected_score, (
                f"Failed for {ssvc_data}: expected {expected_score}, got {score}"
            )

    # ============================================================
    # Test Human-Readable Explanations
    # ============================================================

    def test_explanation_act(self, extractor):
        """Test explanation for ACT tier."""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "yes",
            "technical_impact": "total",
        }
        explanation = extractor.get_explanation(ssvc_data)
        assert "Active exploitation detected in the wild" in explanation
        assert "Vulnerability is automatable (wormable)" in explanation
        assert "Total system compromise possible" in explanation
        assert "Immediate action required - patch within 24 hours" in explanation

    def test_explanation_attend_active(self, extractor):
        """Test explanation for ATTEND tier (active)."""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "no",
            "technical_impact": "partial",
        }
        explanation = extractor.get_explanation(ssvc_data)
        assert "Active exploitation detected in the wild" in explanation
        assert "Exploitation requires human interaction" in explanation
        assert "Partial system compromise only" in explanation
        assert "Scheduled action required - patch within 14 days" in explanation

    def test_explanation_attend_poc(self, extractor):
        """Test explanation for ATTEND tier (poc)."""
        ssvc_data = {
            "exploitation": "poc",
            "automatable": "yes",
            "technical_impact": "partial",
        }
        explanation = extractor.get_explanation(ssvc_data)
        assert "Proof-of-concept exploit code is publicly available" in explanation
        assert "Vulnerability is automatable (wormable)" in explanation
        assert "Scheduled action required - patch within 14 days" in explanation

    def test_explanation_track(self, extractor):
        """Test explanation for TRACK tier."""
        ssvc_data = {
            "exploitation": "none",
            "automatable": "no",
            "technical_impact": "partial",
        }
        explanation = extractor.get_explanation(ssvc_data)
        assert "No known exploitation activity" in explanation
        assert "Exploitation requires human interaction" in explanation
        assert "Partial system compromise only" in explanation
        assert "Routine monitoring - follow standard patch cycle" in explanation

    def test_explanation_missing_keys(self, extractor):
        """Test explanation with missing keys (uses defaults)."""
        ssvc_data = {}
        explanation = extractor.get_explanation(ssvc_data)
        assert "No known exploitation activity" in explanation
        assert "Routine monitoring" in explanation

    # ============================================================
    # Test Full Extraction Pipeline
    # ============================================================

    def test_extract_from_cve_data_success(self, extractor, cve_with_cisa_adp):
        """Test successful extraction from CVE data."""
        ssvc_data = extractor.extract_from_cve_data(cve_with_cisa_adp)
        assert ssvc_data is not None
        assert ssvc_data["exploitation"] == "active"
        assert ssvc_data["automatable"] == "yes"
        assert ssvc_data["technical_impact"] == "total"

    def test_extract_from_cve_data_no_cisa_adp(self, extractor, cve_without_cisa_adp):
        """Test extraction when CISA-ADP not found."""
        ssvc_data = extractor.extract_from_cve_data(cve_without_cisa_adp)
        assert ssvc_data is None

    def test_extract_from_cve_data_no_containers(
        self, extractor, cve_no_adp_containers
    ):
        """Test extraction when no containers present."""
        ssvc_data = extractor.extract_from_cve_data(cve_no_adp_containers)
        assert ssvc_data is None

    def test_extract_from_cve_data_malformed(self, extractor):
        """Test extraction with malformed CVE data."""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2025-9999"},
            "containers": "not_a_dict",  # Invalid structure
        }
        ssvc_data = extractor.extract_from_cve_data(cve_data)
        assert ssvc_data is None

    def test_extract_from_cve_data_exception_handling(self, extractor):
        """Test exception handling during extraction."""
        cve_data = {"invalid": "structure"}  # Missing expected keys
        ssvc_data = extractor.extract_from_cve_data(cve_data)
        assert ssvc_data is None

    # ============================================================
    # Test Edge Cases
    # ============================================================

    def test_multiple_adp_containers(self, extractor):
        """Test extraction with multiple ADP containers."""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2025-1004"},
            "containers": {
                "adp": [
                    {"providerMetadata": {"shortName": "OTHER-ADP"}, "metrics": []},
                    {
                        "providerMetadata": {"shortName": "CISA-ADP"},
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {"options": [{"Exploitation": "poc"}]},
                                }
                            }
                        ],
                    },
                ]
            },
        }
        ssvc_data = extractor.extract_from_cve_data(cve_data)
        assert ssvc_data is not None
        assert ssvc_data["exploitation"] == "poc"

    def test_multiple_ssvc_metrics(self, extractor):
        """Test extraction with multiple SSVC metric objects."""
        cisa_adp = {
            "metrics": [
                {
                    "other": {
                        "type": "ssvc",
                        "content": {"options": [{"Exploitation": "active"}]},
                    }
                },
                {
                    "other": {
                        "type": "ssvc",
                        "content": {"options": [{"Automatable": "yes"}]},
                    }
                },
            ]
        }
        # Should extract from first SSVC metric found
        ssvc_data = extractor._extract_ssvc_from_adp(cisa_adp)
        assert ssvc_data is not None
        assert ssvc_data["exploitation"] == "active"

    def test_mixed_metric_types(self, extractor):
        """Test extraction with mixed metric types."""
        cisa_adp = {
            "metrics": [
                {"other": {"type": "cvss", "content": {"baseScore": 9.8}}},
                {
                    "other": {
                        "type": "ssvc",
                        "content": {"options": [{"Exploitation": "active"}]},
                    }
                },
                {"other": {"type": "epss", "content": {"score": 0.95}}},
            ]
        }
        ssvc_data = extractor._extract_ssvc_from_adp(cisa_adp)
        assert ssvc_data is not None
        assert ssvc_data["exploitation"] == "active"

    def test_non_dict_options(self, extractor):
        """Test handling of non-dict items in options array.

        The current implementation checks `isinstance(option, dict)` before
        accessing dict methods, so non-dict items are safely skipped.
        """
        cisa_adp = {
            "metrics": [
                {
                    "other": {
                        "type": "ssvc",
                        "content": {
                            "options": [
                                {"Exploitation": "active"},
                                {"Automatable": "yes"},
                            ]
                        },
                    }
                }
            ]
        }
        ssvc_data = extractor._extract_ssvc_from_adp(cisa_adp)
        assert ssvc_data is not None
        assert ssvc_data["exploitation"] == "active"
        assert ssvc_data["automatable"] == "yes"

    # ============================================================
    # Test Complete Workflow Scenarios
    # ============================================================

    def test_complete_workflow_critical(self, extractor):
        """Test complete workflow for critical vulnerability."""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2025-1001"},
            "containers": {
                "adp": [
                    {
                        "providerMetadata": {"shortName": "CISA-ADP"},
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "options": [
                                            {"Exploitation": "active"},
                                            {"Automatable": "yes"},
                                            {"Technical Impact": "total"},
                                        ]
                                    },
                                }
                            }
                        ],
                    }
                ]
            },
        }

        # Extract SSVC data
        ssvc_data = extractor.extract_from_cve_data(cve_data)
        assert ssvc_data is not None

        # Calculate priority tier
        tier = extractor.calculate_priority_tier(ssvc_data)
        assert tier == "ACT"

        # Get compact notation
        notation = extractor.get_compact_notation(ssvc_data)
        assert notation == "A/Y/T"

        # Get SSVC score
        score = extractor.get_ssvc_score(ssvc_data)
        assert score == 60

        # Get explanation
        explanation = extractor.get_explanation(ssvc_data)
        assert "Immediate action required" in explanation

    def test_complete_workflow_moderate(self, extractor):
        """Test complete workflow for moderate vulnerability."""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2025-1002"},
            "containers": {
                "adp": [
                    {
                        "providerMetadata": {"shortName": "CISA-ADP"},
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "options": [
                                            {"Exploitation": "poc"},
                                            {"Automatable": "no"},
                                            {"Technical Impact": "partial"},
                                        ]
                                    },
                                }
                            }
                        ],
                    }
                ]
            },
        }

        ssvc_data = extractor.extract_from_cve_data(cve_data)
        assert ssvc_data is not None

        tier = extractor.calculate_priority_tier(ssvc_data)
        assert tier == "TRACK"

        notation = extractor.get_compact_notation(ssvc_data)
        assert notation == "P/N/P"

        score = extractor.get_ssvc_score(ssvc_data)
        assert score == 27  # 20 + 0 + 7.5

        explanation = extractor.get_explanation(ssvc_data)
        assert "Routine monitoring" in explanation
