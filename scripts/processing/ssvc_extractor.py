"""
SSVC (Stakeholder-Specific Vulnerability Categorization) Extractor

Extracts SSVC decision tree data from CISA ADP containers in CVE 5.0 JSON files.

SSVC Framework (CISA Decision Tree):
- Exploitation: active | poc | none
- Automatable: yes | no
- Technical Impact: total | partial

Priority Tiers:
- ACT (Immediate): active + yes + total = Critical priority, patch within 24h
- ATTEND (Scheduled): active OR (poc + yes) = High priority, patch within 14d
- TRACK (Routine): Everything else = Standard cycle monitoring

References:
- CISA SSVC Guide: https://www.cisa.gov/ssvc
- CVE 5.0 Schema: https://github.com/CVEProject/cve-schema
"""

from typing import Dict, Optional
import structlog

logger = structlog.get_logger(__name__)


class SSVCExtractor:
    """Extract SSVC metrics from CVE 5.0 ADP containers"""

    # Valid SSVC decision point values
    EXPLOITATION_VALUES = {"active", "poc", "none"}
    AUTOMATABLE_VALUES = {"yes", "no"}
    TECHNICAL_IMPACT_VALUES = {"total", "partial"}

    def extract_from_cve_data(self, cve_data: Dict) -> Optional[Dict]:
        """
        Extract SSVC data from CVE 5.0 JSON

        Args:
            cve_data: Parsed CVE 5.0 JSON dictionary

        Returns:
            SSVC data dict with exploitation, automatable, technical_impact,
            or None if no CISA-ADP container found
        """
        try:
            # Find CISA-ADP container
            cisa_adp = self._find_cisa_adp(cve_data)

            if not cisa_adp:
                logger.debug(
                    "No CISA-ADP container found",
                    cve_id=cve_data.get("cveMetadata", {}).get("cveId")
                )
                return None

            # Extract SSVC metrics
            ssvc_data = self._extract_ssvc_from_adp(cisa_adp)

            if ssvc_data:
                logger.debug(
                    "Extracted SSVC data",
                    cve_id=cve_data.get("cveMetadata", {}).get("cveId"),
                    ssvc_data=ssvc_data
                )

            return ssvc_data

        except Exception as e:
            logger.error(
                "Failed to extract SSVC data",
                cve_id=cve_data.get("cveMetadata", {}).get("cveId", "unknown"),
                error=str(e)
            )
            return None

    def _find_cisa_adp(self, cve_data: Dict) -> Optional[Dict]:
        """
        Find CISA ADP container in CVE data

        Args:
            cve_data: CVE 5.0 JSON

        Returns:
            CISA ADP container dict or None
        """
        containers = cve_data.get("containers", {})
        adp_list = containers.get("adp", [])

        for adp in adp_list:
            provider = adp.get("providerMetadata", {})
            if provider.get("shortName") == "CISA-ADP":
                return adp

        return None

    def _extract_ssvc_from_adp(self, cisa_adp: Dict) -> Optional[Dict]:
        """
        Extract SSVC decision points from CISA ADP container

        CISA-ADP structure:
        {
          "metrics": [
            {
              "other": {
                "type": "ssvc",
                "content": {
                  "options": [
                    {"Exploitation": "active"},
                    {"Automatable": "yes"},
                    {"Technical Impact": "total"}
                  ]
                }
              }
            }
          ]
        }

        Args:
            cisa_adp: CISA ADP container

        Returns:
            SSVC data dict or None if not found
        """
        ssvc_data = {
            "exploitation": "none",  # Default: no exploitation
            "automatable": "no",     # Default: not automatable
            "technical_impact": "partial"  # Default: partial impact
        }

        metrics = cisa_adp.get("metrics", [])

        for metric in metrics:
            other = metric.get("other", {})

            # Check if this is an SSVC metric
            if other.get("type") != "ssvc":
                continue

            content = other.get("content", {})
            options = content.get("options", [])

            # Extract decision points from options array
            for option in options:
                if isinstance(option, dict):
                    # Check for Exploitation
                    if "Exploitation" in option:
                        value = option["Exploitation"].lower()
                        if value in self.EXPLOITATION_VALUES:
                            ssvc_data["exploitation"] = value
                        else:
                            logger.warning(
                                f"Invalid SSVC Exploitation value: {value}"
                            )

                    # Check for Automatable
                    if "Automatable" in option:
                        value = option["Automatable"].lower()
                        if value in self.AUTOMATABLE_VALUES:
                            ssvc_data["automatable"] = value
                        else:
                            logger.warning(
                                f"Invalid SSVC Automatable value: {value}"
                            )

                    # Check for Technical Impact
                    if "Technical Impact" in option:
                        value = option["Technical Impact"].lower()
                        if value in self.TECHNICAL_IMPACT_VALUES:
                            ssvc_data["technical_impact"] = value
                        else:
                            logger.warning(
                                f"Invalid SSVC Technical Impact value: {value}"
                            )

            # If we found SSVC data, return it
            if any(option.get("Exploitation") or option.get("Automatable")
                   or option.get("Technical Impact") for option in options):
                return ssvc_data

        # No SSVC metric found
        return None

    def calculate_priority_tier(self, ssvc_data: Dict) -> str:
        """
        Calculate CISA priority tier from SSVC decision points

        Priority Tiers (CISA SSVC Decision Tree):
        - ACT: active + yes + total = Immediate action required (24h patch)
        - ATTEND: active OR (poc + yes) = Scheduled action (14d patch)
        - TRACK: Everything else = Routine monitoring

        Args:
            ssvc_data: SSVC decision points

        Returns:
            Priority tier: "ACT", "ATTEND", or "TRACK"
        """
        exploitation = ssvc_data.get("exploitation", "none")
        automatable = ssvc_data.get("automatable", "no")
        technical_impact = ssvc_data.get("technical_impact", "partial")

        # ACT: Active exploitation + Automatable + Total impact
        if (exploitation == "active" and
            automatable == "yes" and
            technical_impact == "total"):
            return "ACT"

        # ATTEND: Active exploitation OR (PoC + Automatable)
        if exploitation == "active":
            return "ATTEND"

        if exploitation == "poc" and automatable == "yes":
            return "ATTEND"

        # TRACK: Everything else
        return "TRACK"

    def get_compact_notation(self, ssvc_data: Dict) -> str:
        """
        Get compact A/Y/T notation for dashboard display

        Examples:
        - A/Y/T = Active/Yes/Total = ACT tier (CRITICAL)
        - A/N/P = Active/No/Partial = ATTEND tier (HIGH)
        - P/Y/T = PoC/Yes/Total = ATTEND tier (HIGH)
        - N/N/P = None/No/Partial = TRACK tier (NORMAL)

        Args:
            ssvc_data: SSVC decision points

        Returns:
            Compact notation string (e.g., "A/Y/T")
        """
        exploitation = ssvc_data.get("exploitation", "none")
        automatable = ssvc_data.get("automatable", "no")
        technical_impact = ssvc_data.get("technical_impact", "partial")

        # Map to first letter (uppercase)
        exploitation_code = {
            "active": "A",
            "poc": "P",
            "none": "N"
        }.get(exploitation, "?")

        automatable_code = {
            "yes": "Y",
            "no": "N"
        }.get(automatable, "?")

        technical_impact_code = {
            "total": "T",
            "partial": "P"
        }.get(technical_impact, "?")

        return f"{exploitation_code}/{automatable_code}/{technical_impact_code}"

    def get_ssvc_score(self, ssvc_data: Dict) -> int:
        """
        Calculate numerical SSVC score (0-100) for risk scoring integration

        Weighting:
        - Exploitation: 30 points (active=30, poc=20, none=0)
        - Automatable: 15 points (yes=15, no=0)
        - Technical Impact: 15 points (total=15, partial=7.5)

        Args:
            ssvc_data: SSVC decision points

        Returns:
            SSVC score (0-60 range, represents 60% of final risk score)
        """
        score = 0

        # Exploitation component (30 points max)
        exploitation_scores = {
            "active": 30,
            "poc": 20,
            "none": 0
        }
        score += exploitation_scores.get(
            ssvc_data.get("exploitation", "none"), 0
        )

        # Automatable component (15 points max)
        automatable_scores = {
            "yes": 15,
            "no": 0
        }
        score += automatable_scores.get(
            ssvc_data.get("automatable", "no"), 0
        )

        # Technical Impact component (15 points max)
        technical_impact_scores = {
            "total": 15,
            "partial": 7.5
        }
        score += technical_impact_scores.get(
            ssvc_data.get("technical_impact", "partial"), 0
        )

        return int(score)

    def get_explanation(self, ssvc_data: Dict) -> str:
        """
        Get human-readable explanation of SSVC assessment

        Args:
            ssvc_data: SSVC decision points

        Returns:
            Explanation string
        """
        exploitation = ssvc_data.get("exploitation", "none")
        automatable = ssvc_data.get("automatable", "no")
        technical_impact = ssvc_data.get("technical_impact", "partial")
        tier = self.calculate_priority_tier(ssvc_data)

        explanations = {
            "exploitation": {
                "active": "Active exploitation detected in the wild",
                "poc": "Proof-of-concept exploit code is publicly available",
                "none": "No known exploitation activity"
            },
            "automatable": {
                "yes": "Vulnerability is automatable (wormable)",
                "no": "Exploitation requires human interaction"
            },
            "technical_impact": {
                "total": "Total system compromise possible",
                "partial": "Partial system compromise only"
            }
        }

        parts = [
            explanations["exploitation"].get(exploitation, ""),
            explanations["automatable"].get(automatable, ""),
            explanations["technical_impact"].get(technical_impact, "")
        ]

        explanation = ". ".join(filter(None, parts))

        tier_guidance = {
            "ACT": "Immediate action required - patch within 24 hours",
            "ATTEND": "Scheduled action required - patch within 14 days",
            "TRACK": "Routine monitoring - follow standard patch cycle"
        }

        return f"{explanation}. Priority: {tier_guidance.get(tier, '')}."
