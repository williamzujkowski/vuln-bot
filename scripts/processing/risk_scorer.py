"""Risk scoring algorithm for vulnerabilities."""

from datetime import datetime, timezone
from typing import Dict, List

import structlog

from scripts.models import ExploitationStatus, SeverityLevel, Vulnerability


class RiskScorer:
    """Calculate risk scores for vulnerabilities based on multiple factors."""

    # SSVC-Enhanced Weight Configuration
    # Total: 100% = 60% SSVC + 25% Traditional + 15% Context
    WEIGHTS = {
        # SSVC Components (60% total) - CISA decision tree framework
        "ssvc_exploitation": 0.30,  # Active/PoC/None exploitation
        "ssvc_automatable": 0.15,  # Wormable assessment
        "ssvc_technical_impact": 0.15,  # Total/Partial compromise
        # Traditional Metrics (25% total)
        "cvss_score": 0.15,  # Base CVSS score (reduced from 25%)
        "epss_score": 0.10,  # Exploit prediction (reduced from 20%)
        # Context (15% total)
        "kev_status": 0.10,  # CISA KEV listing (explicit factor)
        "attack_vector": 0.05,  # Network vs local attack
        # Legacy factors (deprecated in SSVC-enhanced mode)
        "age": 0.00,  # Covered by SSVC exploitation
        "references": 0.00,  # Less predictive than SSVC
        "vendor_impact": 0.00,  # Context-specific filtering
        "complexity": 0.00,  # Covered by SSVC automatable
    }

    # High-impact vendors/products (infrastructure focus)
    HIGH_IMPACT_VENDORS = {
        "microsoft",
        "apache",
        "nginx",
        "oracle",
        "cisco",
        "vmware",
        "citrix",
        "f5",
        "fortinet",
        "paloaltonetworks",
        "kubernetes",
        "docker",
        "jenkins",
        "gitlab",
        "github",
        "amazon",
        "google",
        "ibm",
        "redhat",
        "ubuntu",
    }

    HIGH_IMPACT_PRODUCTS = {
        "windows",
        "exchange",
        "sharepoint",
        "active_directory",
        "apache_http_server",
        "nginx",
        "tomcat",
        "mysql",
        "postgresql",
        "elasticsearch",
        "redis",
        "mongodb",
        "rabbitmq",
        "kafka",
        "kubernetes",
        "docker",
        "openshift",
        "ansible",
        "terraform",
    }

    # Infrastructure-related tags that increase risk
    INFRASTRUCTURE_TAGS = {
        "remote",
        "authentication",
        "privilege_escalation",
        "rce",
        "network",
        "bypass",
        "injection",
        "deserialization",
        "xxe",
        "ssrf",
        "directory_traversal",
        "file_upload",
    }

    def __init__(self):
        """Initialize risk scorer."""
        self.logger = structlog.get_logger(self.__class__.__name__)

    def calculate_risk_score(self, vulnerability: Vulnerability) -> int:
        """Calculate SSVC-enhanced risk score (0-100) for a vulnerability.

        New Formula (SSVC-dominant):
        - 60% SSVC (exploitation + automatable + technical_impact)
        - 25% Traditional (CVSS + EPSS)
        - 15% Context (KEV + attack_vector)

        Args:
            vulnerability: Vulnerability to score

        Returns:
            Risk score between 0 and 100
        """
        scores = {}

        # ===== SSVC COMPONENTS (60% total weight) =====
        if vulnerability.ssvc_data:
            # SSVC scores are pre-calculated in SSVCExtractor (0-60 range)
            # But we normalize here for individual component tracking

            # 1. SSVC Exploitation (30 points max)
            exploitation_scores = {
                "active": 100,  # Will be weighted at 30%
                "poc": 67,  # 2/3 of max
                "none": 0,
            }
            scores["ssvc_exploitation"] = exploitation_scores.get(
                vulnerability.ssvc_data.exploitation, 0
            )

            # 2. SSVC Automatable (15 points max)
            automatable_scores = {
                "yes": 100,  # Will be weighted at 15%
                "no": 0,
            }
            scores["ssvc_automatable"] = automatable_scores.get(
                vulnerability.ssvc_data.automatable, 0
            )

            # 3. SSVC Technical Impact (15 points max)
            technical_impact_scores = {
                "total": 100,  # Will be weighted at 15%
                "partial": 50,  # Half of max
            }
            scores["ssvc_technical_impact"] = technical_impact_scores.get(
                vulnerability.ssvc_data.technical_impact, 0
            )
        else:
            # No SSVC data available - fall back to traditional scoring
            # Map exploitation_status to SSVC-like scores
            exploitation_scores_fallback = {
                ExploitationStatus.ACTIVE: 100,
                ExploitationStatus.WEAPONIZED: 90,
                ExploitationStatus.POC: 67,
                ExploitationStatus.NONE: 0,
                ExploitationStatus.UNKNOWN: 33,
            }
            scores["ssvc_exploitation"] = exploitation_scores_fallback.get(
                vulnerability.exploitation_status, 33
            )
            scores["ssvc_automatable"] = 0  # Unknown without SSVC
            scores["ssvc_technical_impact"] = 0  # Unknown without SSVC

        # ===== TRADITIONAL METRICS (25% total weight) =====

        # 4. CVSS Score Component (15% weight)
        cvss_score = vulnerability.cvss_base_score or 0.0
        scores["cvss_score"] = (cvss_score / 10.0) * 100

        # 5. EPSS Score Component (10% weight)
        epss_prob = vulnerability.epss_probability or 0.0
        scores["epss_score"] = epss_prob

        # ===== CONTEXT FACTORS (15% total weight) =====

        # 6. KEV Status Component (10% weight)
        # Explicit KEV listing is strongest indicator
        kev_scores = {
            ExploitationStatus.ACTIVE: 100,  # In KEV catalog
            ExploitationStatus.WEAPONIZED: 80,  # Likely KEV candidate
            ExploitationStatus.POC: 30,  # Watch for KEV addition
            ExploitationStatus.NONE: 0,
            ExploitationStatus.UNKNOWN: 20,  # Unknown status
        }
        scores["kev_status"] = kev_scores.get(vulnerability.exploitation_status, 20)

        # 7. Attack Vector Component (5% weight)
        attack_vector_scores = {
            "N": 100,  # Network - remotely exploitable
            "A": 70,  # Adjacent - local network
            "L": 40,  # Local - local access required
            "P": 20,  # Physical - physical access required
        }
        scores["attack_vector"] = attack_vector_scores.get(
            vulnerability.attack_vector, 50
        )

        # Legacy factors (0% weight in SSVC mode, kept for fallback compatibility)
        scores["age"] = 0
        scores["references"] = 0
        scores["vendor_impact"] = 0
        scores["complexity"] = 0

        # Calculate weighted score
        weighted_score = sum(
            scores.get(factor, 0) * weight for factor, weight in self.WEIGHTS.items()
        )

        # Ensure score is within bounds
        final_score = int(min(100, max(0, weighted_score)))

        # Log scoring details
        log_data = {
            "cve_id": vulnerability.cve_id,
            "final_score": final_score,
            "component_scores": {
                "ssvc": scores.get("ssvc_exploitation", 0) * 0.30
                + scores.get("ssvc_automatable", 0) * 0.15
                + scores.get("ssvc_technical_impact", 0) * 0.15,
                "traditional": scores.get("cvss_score", 0) * 0.15
                + scores.get("epss_score", 0) * 0.10,
                "context": scores.get("kev_status", 0) * 0.10
                + scores.get("attack_vector", 0) * 0.05,
            },
            "has_ssvc": vulnerability.ssvc_data is not None,
        }

        if vulnerability.ssvc_data:
            log_data["ssvc_priority_tier"] = vulnerability.ssvc_data.priority_tier
            log_data["ssvc_notation"] = vulnerability.ssvc_data.compact_notation

        self.logger.debug("Calculated SSVC-enhanced risk score", **log_data)

        return final_score

    def score_batch(self, vulnerabilities: List[Vulnerability]) -> None:
        """Calculate and assign risk scores to a batch of vulnerabilities.

        Args:
            vulnerabilities: List of vulnerabilities to score
        """
        self.logger.info("Scoring vulnerability batch", count=len(vulnerabilities))

        for vuln in vulnerabilities:
            vuln.risk_score = self.calculate_risk_score(vuln)

        # Log score distribution
        score_ranges = {
            "critical": sum(1 for v in vulnerabilities if v.risk_score >= 90),
            "high": sum(1 for v in vulnerabilities if 70 <= v.risk_score < 90),
            "medium": sum(1 for v in vulnerabilities if 40 <= v.risk_score < 70),
            "low": sum(1 for v in vulnerabilities if v.risk_score < 40),
        }

        self.logger.info("Risk score distribution", **score_ranges)

    def get_risk_factors(self, vulnerability: Vulnerability) -> Dict[str, str]:
        """Get human-readable risk factors for a vulnerability.

        Args:
            vulnerability: Vulnerability to analyze

        Returns:
            Dictionary of risk factor descriptions
        """
        factors = {}

        # CVSS severity
        if vulnerability.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            factors["severity"] = f"{vulnerability.severity.value} severity"

        # EPSS score
        if vulnerability.epss_probability and vulnerability.epss_probability > 50:
            factors["epss"] = f"{vulnerability.epss_probability}% exploit probability"

        # Exploitation status
        if vulnerability.exploitation_status in [
            ExploitationStatus.ACTIVE,
            ExploitationStatus.WEAPONIZED,
        ]:
            factors["exploitation"] = (
                f"Known {vulnerability.exploitation_status.value.lower()} exploitation"
            )

        # Age
        # Ensure datetime is timezone-aware
        published_date = vulnerability.published_date
        if published_date.tzinfo is None:
            published_date = published_date.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - published_date).days
        if age_days <= 7:
            factors["age"] = "Published within last week"
        elif age_days <= 30:
            factors["age"] = "Published within last month"

        # High-impact vendors
        affected_vendors_lower = {v.lower() for v in vulnerability.affected_vendors}
        high_impact_matches = affected_vendors_lower.intersection(
            self.HIGH_IMPACT_VENDORS
        )
        if high_impact_matches:
            factors["vendors"] = (
                f"Affects critical infrastructure: {', '.join(high_impact_matches)}"
            )

        # Attack vector
        if vulnerability.attack_vector == "N":
            factors["vector"] = "Network-based attack vector"

        # No user interaction required
        if vulnerability.requires_user_interaction is False:
            factors["interaction"] = "No user interaction required"

        # No privileges required
        if vulnerability.requires_privileges == "N":
            factors["privileges"] = "No privileges required"

        return factors
