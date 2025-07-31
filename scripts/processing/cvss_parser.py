"""Enhanced CVSS vector parsing for extracting detailed attack metrics."""

import re
from typing import Dict, Optional, Tuple

import structlog


class CVSSVectorParser:
    """Parse CVSS vector strings to extract detailed attack metrics."""

    def __init__(self):
        """Initialize the CVSS parser."""
        self.logger = structlog.get_logger(self.__class__.__name__)

        # CVSS v3.x metric mappings
        self.cvss3_mappings = {
            "AV": {  # Attack Vector
                "N": "Network",
                "A": "Adjacent Network", 
                "L": "Local",
                "P": "Physical"
            },
            "AC": {  # Attack Complexity
                "L": "Low",
                "H": "High"
            },
            "PR": {  # Privileges Required
                "N": "None",
                "L": "Low", 
                "H": "High"
            },
            "UI": {  # User Interaction
                "N": "None",
                "R": "Required"
            },
            "S": {   # Scope
                "U": "Unchanged",
                "C": "Changed"
            },
            "C": {   # Confidentiality Impact
                "N": "None",
                "L": "Low",
                "H": "High"
            },
            "I": {   # Integrity Impact
                "N": "None", 
                "L": "Low",
                "H": "High"
            },
            "A": {   # Availability Impact
                "N": "None",
                "L": "Low", 
                "H": "High"
            }
        }

        # CVSS v2 metric mappings
        self.cvss2_mappings = {
            "AV": {  # Access Vector
                "L": "Local",
                "A": "Adjacent Network",
                "N": "Network"
            },
            "AC": {  # Access Complexity
                "H": "High",
                "M": "Medium",
                "L": "Low"
            },
            "Au": {  # Authentication
                "M": "Multiple",
                "S": "Single",
                "N": "None"
            },
            "C": {   # Confidentiality Impact
                "N": "None",
                "P": "Partial", 
                "C": "Complete"
            },
            "I": {   # Integrity Impact
                "N": "None",
                "P": "Partial",
                "C": "Complete"
            },
            "A": {   # Availability Impact
                "N": "None",
                "P": "Partial",
                "C": "Complete"
            }
        }

    def parse_cvss_vector(self, vector_string: str) -> Dict[str, str]:
        """Parse CVSS vector string and extract all components.
        
        Args:
            vector_string: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            
        Returns:
            Dictionary with parsed CVSS components
        """
        result = {
            "attack_vector": "Unknown",
            "attack_complexity": "Unknown", 
            "privileges_required": "Unknown",
            "user_interaction": "Unknown",
            "scope": "Unknown",
            "confidentiality_impact": "Unknown",
            "integrity_impact": "Unknown",
            "availability_impact": "Unknown",
            "version": "Unknown"
        }

        if not vector_string:
            return result

        try:
            # Determine CVSS version
            version = self._detect_cvss_version(vector_string)
            result["version"] = version

            if version.startswith("3."):
                return self._parse_cvss3_vector(vector_string, result)
            elif version.startswith("2."):
                return self._parse_cvss2_vector(vector_string, result)
            else:
                self.logger.warning("Unknown CVSS version", vector=vector_string)
                return result

        except Exception as e:
            self.logger.error(
                "Failed to parse CVSS vector",
                vector=vector_string,
                error=str(e)
            )
            return result

    def _detect_cvss_version(self, vector_string: str) -> str:
        """Detect CVSS version from vector string."""
        if vector_string.startswith("CVSS:3.1"):
            return "3.1"
        elif vector_string.startswith("CVSS:3.0"):
            return "3.0"
        elif "/PR:" in vector_string or "/UI:" in vector_string:
            # CVSS v3 specific metrics
            return "3.1"  # Default to 3.1 if unclear
        elif "/Au:" in vector_string:
            # CVSS v2 specific metric
            return "2.0"
        else:
            # Try to infer from pattern
            if re.match(r"AV:[NAL]/AC:[LH]/PR:[NLH]/UI:[NR]", vector_string):
                return "3.1"
            elif re.match(r"AV:[NAL]/AC:[HML]/Au:[MSN]", vector_string):
                return "2.0"
            
        return "Unknown"

    def _parse_cvss3_vector(self, vector_string: str, result: Dict[str, str]) -> Dict[str, str]:
        """Parse CVSS v3.x vector string."""
        # Extract metric values using regex
        metrics = re.findall(r"([A-Z]+):([A-Z])", vector_string)
        
        for metric, value in metrics:
            if metric == "AV":
                result["attack_vector"] = self.cvss3_mappings["AV"].get(value, f"Unknown ({value})")
            elif metric == "AC":
                result["attack_complexity"] = self.cvss3_mappings["AC"].get(value, f"Unknown ({value})")
            elif metric == "PR":
                result["privileges_required"] = self.cvss3_mappings["PR"].get(value, f"Unknown ({value})")
            elif metric == "UI":
                result["user_interaction"] = self.cvss3_mappings["UI"].get(value, f"Unknown ({value})")
            elif metric == "S":
                result["scope"] = self.cvss3_mappings["S"].get(value, f"Unknown ({value})")
            elif metric == "C":
                result["confidentiality_impact"] = self.cvss3_mappings["C"].get(value, f"Unknown ({value})")
            elif metric == "I":
                result["integrity_impact"] = self.cvss3_mappings["I"].get(value, f"Unknown ({value})")
            elif metric == "A":
                result["availability_impact"] = self.cvss3_mappings["A"].get(value, f"Unknown ({value})")

        return result

    def _parse_cvss2_vector(self, vector_string: str, result: Dict[str, str]) -> Dict[str, str]:
        """Parse CVSS v2.0 vector string."""
        # Extract metric values using regex
        metrics = re.findall(r"([A-Z][a-z]?):([A-Z])", vector_string)
        
        for metric, value in metrics:
            if metric == "AV":
                result["attack_vector"] = self.cvss2_mappings["AV"].get(value, f"Unknown ({value})")
            elif metric == "AC":
                result["attack_complexity"] = self.cvss2_mappings["AC"].get(value, f"Unknown ({value})")
            elif metric == "Au":
                # Map authentication to privileges required for consistency
                result["privileges_required"] = self.cvss2_mappings["Au"].get(value, f"Unknown ({value})")
                # CVSS v2 doesn't have user interaction, so infer from authentication
                result["user_interaction"] = "Required" if value != "N" else "None"
            elif metric == "C":
                result["confidentiality_impact"] = self.cvss2_mappings["C"].get(value, f"Unknown ({value})")
            elif metric == "I":
                result["integrity_impact"] = self.cvss2_mappings["I"].get(value, f"Unknown ({value})")
            elif metric == "A":
                result["availability_impact"] = self.cvss2_mappings["A"].get(value, f"Unknown ({value})")

        # CVSS v2 doesn't have scope, set default
        result["scope"] = "Not Applicable"

        return result

    def get_attack_vector_priority(self, attack_vector: str) -> int:
        """Get priority score for attack vector (higher = more dangerous)."""
        priority_map = {
            "Network": 4,
            "Adjacent Network": 3,
            "Local": 2,
            "Physical": 1,
            "Unknown": 0
        }
        return priority_map.get(attack_vector, 0)

    def get_complexity_priority(self, complexity: str) -> int:
        """Get priority score for attack complexity (higher = easier to exploit)."""
        priority_map = {
            "Low": 3,
            "Medium": 2,
            "High": 1,
            "Unknown": 0
        }
        return priority_map.get(complexity, 0)

    def get_privileges_priority(self, privileges: str) -> int:
        """Get priority score for privileges required (higher = less privileges needed)."""
        priority_map = {
            "None": 4,
            "Low": 3,
            "Single": 2,
            "High": 1,
            "Multiple": 1,
            "Unknown": 0
        }
        return priority_map.get(privileges, 0)

    def calculate_exploitability_factors(self, parsed_vector: Dict[str, str]) -> Dict[str, int]:
        """Calculate exploitability factor scores from parsed CVSS vector."""
        return {
            "attack_vector_score": self.get_attack_vector_priority(parsed_vector["attack_vector"]),
            "complexity_score": self.get_complexity_priority(parsed_vector["attack_complexity"]),
            "privileges_score": self.get_privileges_priority(parsed_vector["privileges_required"]),
            "user_interaction_score": 2 if parsed_vector["user_interaction"] == "None" else 1
        }