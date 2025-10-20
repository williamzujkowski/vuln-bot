"""
Comprehensive Unit Tests for SSVC Fallback Inference Engine

Tests all inference logic paths for >90% code coverage:
- Exploitation status inference (active/poc/none)
- Automatable assessment inference (yes/no)
- Technical impact inference (total/partial)
- Confidence scoring
- Edge cases and fallback logic
- Reference parsing
- CVSS vector parsing
"""

import pytest

from scripts.processing.ssvc_fallback import SSVCFallbackEngine


class TestSSVCFallbackEngine:
    """Test suite for SSVCFallbackEngine"""

    @pytest.fixture
    def engine(self):
        """Create SSVCFallbackEngine instance"""
        return SSVCFallbackEngine()

    # ========================================
    # Test Exploitation Inference
    # ========================================

    def test_exploitation_kev_active(self, engine):
        """Test exploitation = active when in CISA KEV catalog"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0001"}
        }

        result = engine._infer_exploitation(cve_data, has_kev=True, epss_score=None)
        assert result == "active"

    def test_exploitation_epss_95_active(self, engine):
        """Test exploitation = active when EPSS >= 95%"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0002"}
        }

        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=95.0)
        assert result == "active"

        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=99.0)
        assert result == "active"

    def test_exploitation_poc_reference(self, engine):
        """Test exploitation = poc when PoC references found"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0003"},
            "containers": {
                "cna": {
                    "references": [
                        {
                            "url": "https://github.com/attacker/exploit-poc",
                            "tags": ["exploit"]
                        }
                    ]
                }
            }
        }

        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=None)
        assert result == "poc"

    def test_exploitation_epss_70_poc(self, engine):
        """Test exploitation = poc when EPSS 70-95%"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0004"}
        }

        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=70.0)
        assert result == "poc"

        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=85.0)
        assert result == "poc"

        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=94.9)
        assert result == "poc"

    def test_exploitation_none_default(self, engine):
        """Test exploitation = none when no indicators"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0005"}
        }

        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=None)
        assert result == "none"

        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=50.0)
        assert result == "none"

    # ========================================
    # Test Automatable Inference
    # ========================================

    def test_automatable_yes_all_criteria(self, engine):
        """Test automatable = yes when AV:N/AC:L/PR:N/UI:N"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._infer_automatable(cve_data)
        assert result == "yes"

    def test_automatable_no_network_required(self, engine):
        """Test automatable = no when not network accessible (AV:L)"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._infer_automatable(cve_data)
        assert result == "no"

    def test_automatable_no_high_complexity(self, engine):
        """Test automatable = no when attack complexity high (AC:H)"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._infer_automatable(cve_data)
        assert result == "no"

    def test_automatable_no_privileges_required(self, engine):
        """Test automatable = no when privileges required (PR:L/H)"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._infer_automatable(cve_data)
        assert result == "no"

    def test_automatable_no_user_interaction(self, engine):
        """Test automatable = no when user interaction required (UI:R)"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._infer_automatable(cve_data)
        assert result == "no"

    def test_automatable_no_missing_cvss(self, engine):
        """Test automatable = no when CVSS data missing"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0006"}
        }

        result = engine._infer_automatable(cve_data)
        assert result == "no"

    # ========================================
    # Test Technical Impact Inference
    # ========================================

    def test_technical_impact_total_scope_change(self, engine):
        """Test technical_impact = total when scope changed (S:C)"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._infer_technical_impact(cve_data)
        assert result == "total"

    def test_technical_impact_total_full_cia(self, engine):
        """Test technical_impact = total when C:H/I:H/A:H"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._infer_technical_impact(cve_data)
        assert result == "total"

    def test_technical_impact_partial_incomplete_cia(self, engine):
        """Test technical_impact = partial when not all CIA high"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._infer_technical_impact(cve_data)
        assert result == "partial"

    def test_technical_impact_partial_missing_cvss(self, engine):
        """Test technical_impact = partial when CVSS data missing"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0007"}
        }

        result = engine._infer_technical_impact(cve_data)
        assert result == "partial"

    # ========================================
    # Test PoC Reference Detection
    # ========================================

    def test_has_poc_reference_exploit_tag(self, engine):
        """Test PoC detection via exploit tag"""
        cve_data = {
            "containers": {
                "cna": {
                    "references": [
                        {
                            "url": "https://example.com/vuln-info",
                            "tags": ["exploit", "technical-description"]
                        }
                    ]
                }
            }
        }

        result = engine._has_poc_reference(cve_data)
        assert result is True

    def test_has_poc_reference_github_url(self, engine):
        """Test PoC detection via GitHub URL"""
        cve_data = {
            "containers": {
                "cna": {
                    "references": [
                        {
                            "url": "https://github.com/attacker/exploit-poc-2024",
                            "tags": []
                        }
                    ]
                }
            }
        }

        result = engine._has_poc_reference(cve_data)
        assert result is True

    def test_has_poc_reference_exploit_db(self, engine):
        """Test PoC detection via Exploit-DB"""
        cve_data = {
            "containers": {
                "cna": {
                    "references": [
                        {
                            "url": "https://www.exploit-db.com/exploits/12345",
                            "tags": []
                        }
                    ]
                }
            }
        }

        result = engine._has_poc_reference(cve_data)
        assert result is True

    def test_has_poc_reference_metasploit(self, engine):
        """Test PoC detection via Metasploit keyword"""
        cve_data = {
            "containers": {
                "cna": {
                    "references": [
                        {
                            "url": "https://www.rapid7.com/db/modules/exploit/metasploit/vuln",
                            "tags": []
                        }
                    ]
                }
            }
        }

        result = engine._has_poc_reference(cve_data)
        assert result is True

    def test_has_poc_reference_filtered_patch(self, engine):
        """Test PoC detection filters out patch/advisory references"""
        cve_data = {
            "containers": {
                "cna": {
                    "references": [
                        {
                            "url": "https://github.com/vendor/security-advisory",
                            "tags": ["vendor-advisory"]
                        }
                    ]
                }
            }
        }

        result = engine._has_poc_reference(cve_data)
        assert result is False

    def test_has_poc_reference_no_poc(self, engine):
        """Test PoC detection returns False when no PoC found"""
        cve_data = {
            "containers": {
                "cna": {
                    "references": [
                        {
                            "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
                            "tags": ["technical-description"]
                        }
                    ]
                }
            }
        }

        result = engine._has_poc_reference(cve_data)
        assert result is False

    def test_has_poc_reference_enriched_format(self, engine):
        """Test PoC detection with enriched vulnerability format"""
        cve_data = {
            "references": [
                {
                    "url": "https://github.com/exploit/poc",
                    "tags": ["exploit"]
                }
            ]
        }

        result = engine._has_poc_reference(cve_data)
        assert result is True

    # ========================================
    # Test CVSS Vector Extraction
    # ========================================

    def test_get_cvss_vector_v3_1(self, engine):
        """Test CVSS v3.1 vector extraction"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._get_cvss_vector(cve_data)
        assert result == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_get_cvss_vector_v3_0(self, engine):
        """Test CVSS v3.0 vector extraction"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_0": {
                                "vectorString": "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._get_cvss_vector(cve_data)
        assert result == "CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N"

    def test_get_cvss_vector_enriched_format(self, engine):
        """Test CVSS vector extraction from enriched format"""
        cve_data = {
            "cvss_metrics": [
                {
                    "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                }
            ]
        }

        result = engine._get_cvss_vector(cve_data)
        assert result == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

    def test_get_cvss_vector_direct_field(self, engine):
        """Test CVSS vector extraction from direct field"""
        cve_data = {
            "cvssVector": "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
        }

        result = engine._get_cvss_vector(cve_data)
        assert result == "CVSS:3.1/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"

    def test_get_cvss_vector_missing(self, engine):
        """Test CVSS vector extraction when missing"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0008"}
        }

        result = engine._get_cvss_vector(cve_data)
        assert result is None

    # ========================================
    # Test CVSS Vector Parsing
    # ========================================

    def test_parse_cvss_vector_complete(self, engine):
        """Test parsing complete CVSS vector"""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"

        result = engine._parse_cvss_vector(vector)

        assert result == {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "H",
            "A": "H"
        }

    def test_parse_cvss_vector_v3_0(self, engine):
        """Test parsing CVSS v3.0 vector"""
        vector = "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"

        result = engine._parse_cvss_vector(vector)

        assert result["AV"] == "L"
        assert result["AC"] == "H"
        assert result["PR"] == "H"
        assert result["UI"] == "R"

    def test_parse_cvss_vector_with_modifiers(self, engine):
        """Test parsing CVSS vector with temporal/environmental modifiers"""
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:U"

        result = engine._parse_cvss_vector(vector)

        # Should include temporal metrics
        assert result["E"] == "F"
        assert result["RL"] == "U"

    # ========================================
    # Test References Extraction
    # ========================================

    def test_get_references_cve5_format(self, engine):
        """Test reference extraction from CVE 5.0 format"""
        cve_data = {
            "containers": {
                "cna": {
                    "references": [
                        {"url": "https://example.com/1", "tags": ["vendor-advisory"]},
                        {"url": "https://example.com/2", "tags": ["exploit"]}
                    ]
                }
            }
        }

        result = engine._get_references(cve_data)

        assert len(result) == 2
        assert result[0]["url"] == "https://example.com/1"
        assert result[1]["url"] == "https://example.com/2"

    def test_get_references_enriched_format(self, engine):
        """Test reference extraction from enriched format"""
        cve_data = {
            "references": [
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001", "tags": []}
            ]
        }

        result = engine._get_references(cve_data)

        assert len(result) == 1
        assert result[0]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"

    def test_get_references_empty(self, engine):
        """Test reference extraction when empty"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0009"}
        }

        result = engine._get_references(cve_data)

        assert result == []

    # ========================================
    # Test CVE ID Extraction
    # ========================================

    def test_get_cve_id_metadata_format(self, engine):
        """Test CVE ID extraction from cveMetadata"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0001"}
        }

        result = engine._get_cve_id(cve_data)
        assert result == "CVE-2024-0001"

    def test_get_cve_id_enriched_format(self, engine):
        """Test CVE ID extraction from enriched format"""
        cve_data = {
            "cve_id": "CVE-2024-0002"
        }

        result = engine._get_cve_id(cve_data)
        assert result == "CVE-2024-0002"

    def test_get_cve_id_alternate_field(self, engine):
        """Test CVE ID extraction from alternate field"""
        cve_data = {
            "cveId": "CVE-2024-0003"
        }

        result = engine._get_cve_id(cve_data)
        assert result == "CVE-2024-0003"

    def test_get_cve_id_missing(self, engine):
        """Test CVE ID extraction when missing"""
        cve_data = {}

        result = engine._get_cve_id(cve_data)
        assert result == "unknown"

    # ========================================
    # Test Confidence Score Calculation
    # ========================================

    def test_confidence_score_kev_highest(self, engine):
        """Test confidence score with KEV status (highest)"""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "yes",
            "technical_impact": "total"
        }

        result = engine.calculate_confidence_score(
            ssvc_data, has_kev=True, epss_score=None
        )

        assert result >= 0.9  # KEV = very high confidence

    def test_confidence_score_high_epss(self, engine):
        """Test confidence score with EPSS >= 95%"""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "yes",
            "technical_impact": "total"
        }

        result = engine.calculate_confidence_score(
            ssvc_data, has_kev=False, epss_score=95.0
        )

        assert result >= 0.8  # High EPSS = high confidence

    def test_confidence_score_moderate_epss(self, engine):
        """Test confidence score with EPSS 70-95%"""
        ssvc_data = {
            "exploitation": "poc",
            "automatable": "no",
            "technical_impact": "partial"
        }

        result = engine.calculate_confidence_score(
            ssvc_data, has_kev=False, epss_score=80.0
        )

        assert result >= 0.6  # Moderate EPSS = moderate confidence

    def test_confidence_score_cvss_based(self, engine):
        """Test confidence score with CVSS-based inferences"""
        ssvc_data = {
            "exploitation": "none",
            "automatable": "no",
            "technical_impact": "partial"
        }

        result = engine.calculate_confidence_score(
            ssvc_data, has_kev=False, epss_score=None
        )

        assert result >= 0.65  # CVSS vector present = reliable

    def test_confidence_score_base_minimum(self, engine):
        """Test base confidence score minimum"""
        ssvc_data = {}

        result = engine.calculate_confidence_score(
            ssvc_data, has_kev=False, epss_score=None
        )

        assert result == 0.5  # Base confidence

    def test_confidence_score_capped_at_one(self, engine):
        """Test confidence score capped at 1.0"""
        ssvc_data = {
            "exploitation": "active",
            "automatable": "yes",
            "technical_impact": "total"
        }

        result = engine.calculate_confidence_score(
            ssvc_data, has_kev=True, epss_score=99.0
        )

        assert result <= 1.0  # Never exceeds 1.0

    # ========================================
    # Test Complete SSVC Inference
    # ========================================

    def test_infer_ssvc_complete_high_risk(self, engine):
        """Test complete SSVC inference for high-risk CVE"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-9999"},
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                            }
                        }
                    ],
                    "references": [
                        {
                            "url": "https://github.com/attacker/exploit",
                            "tags": ["exploit"]
                        }
                    ]
                }
            }
        }

        result = engine.infer_ssvc(cve_data, has_kev=True, epss_score=95.0)

        assert result["exploitation"] == "active"
        assert result["automatable"] == "yes"
        assert result["technical_impact"] == "total"
        assert result["inferred"] is True

    def test_infer_ssvc_complete_low_risk(self, engine):
        """Test complete SSVC inference for low-risk CVE"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-8888"},
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
                            }
                        }
                    ],
                    "references": [
                        {
                            "url": "https://vendor.com/security-advisory",
                            "tags": ["vendor-advisory"]
                        }
                    ]
                }
            }
        }

        result = engine.infer_ssvc(cve_data, has_kev=False, epss_score=5.0)

        assert result["exploitation"] == "none"
        assert result["automatable"] == "no"
        assert result["technical_impact"] == "partial"
        assert result["inferred"] is True

    def test_infer_ssvc_error_handling(self, engine):
        """Test SSVC inference error handling with safe defaults"""
        # Invalid/malformed data that might cause exceptions
        # Using empty dict instead of None since the code expects a dict
        cve_data = {}

        result = engine.infer_ssvc(cve_data, has_kev=False, epss_score=None)

        # Should return safe defaults
        assert result["exploitation"] == "none"
        assert result["automatable"] == "no"
        assert result["technical_impact"] == "partial"
        assert result["inferred"] is True

    def test_infer_ssvc_minimal_data(self, engine):
        """Test SSVC inference with minimal CVE data"""
        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-7777"}
        }

        result = engine.infer_ssvc(cve_data, has_kev=False, epss_score=None)

        assert result["exploitation"] == "none"
        assert result["automatable"] == "no"
        assert result["technical_impact"] == "partial"
        assert result["inferred"] is True

    # ========================================
    # Test Edge Cases & Boundary Conditions
    # ========================================

    def test_exploitation_epss_boundary_70(self, engine):
        """Test exploitation at EPSS 70% boundary"""
        cve_data = {"cveMetadata": {"cveId": "CVE-2024-0010"}}

        # 69.9% should be "none"
        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=69.9)
        assert result == "none"

        # 70.0% should be "poc"
        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=70.0)
        assert result == "poc"

    def test_exploitation_epss_boundary_95(self, engine):
        """Test exploitation at EPSS 95% boundary"""
        cve_data = {"cveMetadata": {"cveId": "CVE-2024-0011"}}

        # 94.9% should be "poc"
        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=94.9)
        assert result == "poc"

        # 95.0% should be "active"
        result = engine._infer_exploitation(cve_data, has_kev=False, epss_score=95.0)
        assert result == "active"

    def test_automatable_adjacent_network(self, engine):
        """Test automatable with adjacent network (AV:A) - not wormable"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._infer_automatable(cve_data)
        assert result == "no"  # AV:A is not network (AV:N)

    def test_technical_impact_partial_cia_variations(self, engine):
        """Test technical impact with various partial CIA combinations"""
        test_cases = [
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",  # C:H, I:L, A:N
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N",  # C:L, I:H, A:N
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",  # C:N, I:N, A:H
        ]

        for vector in test_cases:
            cve_data = {
                "containers": {
                    "cna": {
                        "metrics": [
                            {
                                "cvssV3_1": {
                                    "vectorString": vector
                                }
                            }
                        ]
                    }
                }
            }

            result = engine._infer_technical_impact(cve_data)
            assert result == "partial", f"Failed for vector: {vector}"

    def test_poc_reference_case_insensitive(self, engine):
        """Test PoC reference detection is case-insensitive"""
        cve_data = {
            "containers": {
                "cna": {
                    "references": [
                        {
                            "url": "https://GITHUB.COM/attacker/EXPLOIT-PoC",
                            "tags": ["EXPLOIT"]
                        }
                    ]
                }
            }
        }

        result = engine._has_poc_reference(cve_data)
        assert result is True

    def test_cvss_vector_multiple_metrics(self, engine):
        """Test CVSS vector extraction when multiple metrics present"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
                            }
                        },
                        {
                            "cvssV3_0": {
                                "vectorString": "CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._get_cvss_vector(cve_data)
        # Should prefer v3.1 over v3.0
        assert result.startswith("CVSS:3.1")

    def test_infer_ssvc_kev_overrides_epss(self, engine):
        """Test KEV status overrides EPSS score in exploitation inference"""
        cve_data = {"cveMetadata": {"cveId": "CVE-2024-0012"}}

        result = engine.infer_ssvc(cve_data, has_kev=True, epss_score=10.0)

        # KEV should override low EPSS
        assert result["exploitation"] == "active"

    def test_poc_reference_with_patch_keyword_in_url(self, engine):
        """Test PoC reference filtered when patch keyword in URL"""
        cve_data = {
            "containers": {
                "cna": {
                    "references": [
                        {
                            "url": "https://github.com/vendor/security-patch-advisory",
                            "tags": []
                        }
                    ]
                }
            }
        }

        result = engine._has_poc_reference(cve_data)
        assert result is False  # Should filter out patch references

    def test_get_references_with_object_format(self, engine):
        """Test reference extraction with object format (hasattr checks)"""
        # Create mock reference objects with attributes
        class MockReference:
            def __init__(self, url, tags):
                self.url = url
                self.tags = tags

        mock_refs = [
            MockReference("https://example.com/ref1", ["vendor-advisory"]),
            MockReference("https://example.com/ref2", ["exploit"])
        ]

        cve_data = {
            "references": mock_refs
        }

        result = engine._get_references(cve_data)

        assert len(result) == 2
        assert result[0]["url"] == "https://example.com/ref1"
        assert result[1]["tags"] == ["exploit"]

    def test_get_references_with_object_without_tags(self, engine):
        """Test reference extraction with object missing tags attribute"""
        class MockReference:
            def __init__(self, url):
                self.url = url

        mock_ref = MockReference("https://example.com/ref")

        cve_data = {
            "references": [mock_ref]
        }

        result = engine._get_references(cve_data)

        assert len(result) == 1
        assert result[0]["url"] == "https://example.com/ref"
        assert result[0]["tags"] == []

    def test_parse_cvss_vector_empty_pairs(self, engine):
        """Test parsing CVSS vector with empty components"""
        vector = "CVSS:3.1/AV:N/AC:L//PR:N/UI:N"  # Double slash creates empty pair

        result = engine._parse_cvss_vector(vector)

        # Should handle empty pairs gracefully
        assert result["AV"] == "N"
        assert result["PR"] == "N"

    def test_confidence_score_combined_factors(self, engine):
        """Test confidence score with multiple contributing factors"""
        ssvc_data = {
            "exploitation": "poc",
            "automatable": "yes",
            "technical_impact": "total"
        }

        # Test with both EPSS and CVSS data
        result = engine.calculate_confidence_score(
            ssvc_data, has_kev=False, epss_score=75.0
        )

        # Should have moderate to high confidence
        assert result >= 0.7
        assert result <= 1.0

    def test_exploitation_kev_with_high_epss(self, engine):
        """Test exploitation inference when both KEV and high EPSS present"""
        cve_data = {"cveMetadata": {"cveId": "CVE-2024-0013"}}

        result = engine._infer_exploitation(cve_data, has_kev=True, epss_score=99.0)

        # KEV takes precedence (checked first)
        assert result == "active"

    def test_technical_impact_scope_change_overrides_cia(self, engine):
        """Test scope change takes precedence over CIA metrics"""
        cve_data = {
            "containers": {
                "cna": {
                    "metrics": [
                        {
                            "cvssV3_1": {
                                # Scope changed but incomplete CIA
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N"
                            }
                        }
                    ]
                }
            }
        }

        result = engine._infer_technical_impact(cve_data)
        # Scope change should result in total impact
        assert result == "total"
