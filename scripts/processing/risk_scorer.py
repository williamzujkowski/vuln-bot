"""Risk scoring algorithm for vulnerabilities."""

import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set

import structlog

from scripts.models import ExploitationStatus, SeverityLevel, Vulnerability


class RiskScorer:
    """Calculate risk scores for vulnerabilities based on multiple factors."""

    # Weight configuration for different factors
    WEIGHTS = {
        "cvss_score": 0.25,      # Base CVSS score
        "epss_score": 0.20,      # Exploit prediction
        "exploitation": 0.20,    # Known exploitation status
        "age": 0.10,            # How new the vulnerability is
        "references": 0.05,      # Number of references
        "vendor_impact": 0.10,   # Impact based on affected vendors
        "attack_vector": 0.05,   # Network vs local attack
        "complexity": 0.05,      # Attack complexity
    }
    
    # High-impact vendors/products (infrastructure focus)
    HIGH_IMPACT_VENDORS = {
        "microsoft", "apache", "nginx", "oracle", "cisco",
        "vmware", "citrix", "f5", "fortinet", "paloaltonetworks",
        "kubernetes", "docker", "jenkins", "gitlab", "github",
        "amazon", "google", "ibm", "redhat", "ubuntu",
    }
    
    HIGH_IMPACT_PRODUCTS = {
        "windows", "exchange", "sharepoint", "active_directory",
        "apache_http_server", "nginx", "tomcat", "mysql", "postgresql",
        "elasticsearch", "redis", "mongodb", "rabbitmq", "kafka",
        "kubernetes", "docker", "openshift", "ansible", "terraform",
    }
    
    # Infrastructure-related tags that increase risk
    INFRASTRUCTURE_TAGS = {
        "remote", "authentication", "privilege_escalation", "rce",
        "network", "bypass", "injection", "deserialization",
        "xxe", "ssrf", "directory_traversal", "file_upload",
    }

    def __init__(self):
        """Initialize risk scorer."""
        self.logger = structlog.get_logger(self.__class__.__name__)

    def calculate_risk_score(self, vulnerability: Vulnerability) -> int:
        """Calculate risk score (0-100) for a vulnerability.
        
        Args:
            vulnerability: Vulnerability to score
            
        Returns:
            Risk score between 0 and 100
        """
        scores = {}
        
        # 1. CVSS Score Component (normalized to 0-100)
        cvss_score = vulnerability.cvss_base_score or 0.0
        scores["cvss_score"] = (cvss_score / 10.0) * 100
        
        # 2. EPSS Score Component
        epss_prob = vulnerability.epss_probability or 0.0
        scores["epss_score"] = epss_prob
        
        # 3. Exploitation Status Component
        exploitation_scores = {
            ExploitationStatus.ACTIVE: 100,
            ExploitationStatus.WEAPONIZED: 90,
            ExploitationStatus.POC: 70,
            ExploitationStatus.NONE: 30,
            ExploitationStatus.UNKNOWN: 50,
        }
        scores["exploitation"] = exploitation_scores.get(
            vulnerability.exploitation_status, 50
        )
        
        # 4. Age Component (newer = higher risk)
        age_days = (datetime.utcnow() - vulnerability.published_date).days
        if age_days <= 7:
            scores["age"] = 100
        elif age_days <= 30:
            scores["age"] = 80
        elif age_days <= 90:
            scores["age"] = 60
        elif age_days <= 180:
            scores["age"] = 40
        else:
            scores["age"] = 20
        
        # 5. References Component (more references = higher risk)
        ref_count = len(vulnerability.references)
        if ref_count >= 10:
            scores["references"] = 100
        elif ref_count >= 5:
            scores["references"] = 80
        else:
            scores["references"] = ref_count * 16  # Linear scale up to 5
        
        # 6. Vendor Impact Component
        vendor_score = 0
        affected_vendors_lower = {v.lower() for v in vulnerability.affected_vendors}
        affected_products_lower = {p.lower() for p in vulnerability.affected_products}
        
        # Check for high-impact vendors
        high_impact_vendor_count = len(
            affected_vendors_lower.intersection(self.HIGH_IMPACT_VENDORS)
        )
        high_impact_product_count = len(
            affected_products_lower.intersection(self.HIGH_IMPACT_PRODUCTS)
        )
        
        if high_impact_vendor_count > 0 or high_impact_product_count > 0:
            vendor_score = min(100, 50 + (high_impact_vendor_count + high_impact_product_count) * 10)
        else:
            vendor_score = min(100, len(vulnerability.affected_vendors) * 10)
        
        scores["vendor_impact"] = vendor_score
        
        # 7. Attack Vector Component
        attack_vector_scores = {
            "N": 100,  # Network
            "A": 70,   # Adjacent
            "L": 40,   # Local
            "P": 20,   # Physical
        }
        scores["attack_vector"] = attack_vector_scores.get(
            vulnerability.attack_vector, 50
        )
        
        # 8. Complexity Component (based on various factors)
        complexity_score = 50  # Base score
        
        # Adjust based on user interaction requirement
        if vulnerability.requires_user_interaction is False:
            complexity_score += 25
        
        # Adjust based on privilege requirement
        if vulnerability.requires_privileges == "N":  # None required
            complexity_score += 25
        elif vulnerability.requires_privileges == "L":  # Low required
            complexity_score += 10
        
        scores["complexity"] = min(100, complexity_score)
        
        # Apply infrastructure tag bonus
        tag_bonus = 0
        if vulnerability.tags:
            matching_tags = set(t.lower() for t in vulnerability.tags)
            infra_matches = matching_tags.intersection(self.INFRASTRUCTURE_TAGS)
            if infra_matches:
                tag_bonus = min(10, len(infra_matches) * 2)
        
        # Calculate weighted score
        weighted_score = sum(
            scores.get(factor, 0) * weight
            for factor, weight in self.WEIGHTS.items()
        )
        
        # Add tag bonus and ensure score is within bounds
        final_score = int(min(100, max(0, weighted_score + tag_bonus)))
        
        self.logger.debug(
            "Calculated risk score",
            cve_id=vulnerability.cve_id,
            final_score=final_score,
            component_scores=scores,
            tag_bonus=tag_bonus,
        )
        
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
            factors["exploitation"] = f"Known {vulnerability.exploitation_status.value.lower()} exploitation"
        
        # Age
        age_days = (datetime.utcnow() - vulnerability.published_date).days
        if age_days <= 7:
            factors["age"] = "Published within last week"
        elif age_days <= 30:
            factors["age"] = "Published within last month"
        
        # High-impact vendors
        affected_vendors_lower = {v.lower() for v in vulnerability.affected_vendors}
        high_impact_matches = affected_vendors_lower.intersection(self.HIGH_IMPACT_VENDORS)
        if high_impact_matches:
            factors["vendors"] = f"Affects critical infrastructure: {', '.join(high_impact_matches)}"
        
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