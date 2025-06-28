"""Data quality configuration definitions."""

from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class DataQualityConfig:
    """Configuration for data quality checks and validation rules."""

    # Severity filtering
    allowed_severities: Set[str] = field(
        default_factory=lambda: {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    )
    min_severity: str = "HIGH"

    # Score thresholds
    min_cvss_score: float = 0.0
    max_cvss_score: float = 10.0
    min_epss_score: float = 0.0
    max_epss_score: float = 1.0
    min_risk_score: int = 0
    max_risk_score: int = 100

    # Required fields for vulnerability records
    required_fields: List[str] = field(
        default_factory=lambda: [
            "cve_id",
            "title",
            "description",
            "severity",
            "published_date",
            "last_modified_date",
        ]
    )

    # Data validation rules
    max_title_length: int = 500
    max_description_length: int = 5000
    max_vendors_per_vuln: int = 100
    max_products_per_vuln: int = 200
    max_references_per_vuln: int = 50
    max_tags_per_vuln: int = 20

    # CVE ID pattern (CVE-YYYY-NNNNN+)
    cve_id_pattern: str = r"^CVE-\d{4}-\d{4,}$"

    # Date range validation
    min_year: int = 2024
    max_year: int = 2025
    allow_future_dates: bool = False

    # Vendor/Product filtering
    blocked_vendors: Set[str] = field(default_factory=set)
    blocked_products: Set[str] = field(default_factory=set)
    priority_vendors: Set[str] = field(
        default_factory=lambda: {
            "Microsoft",
            "Google",
            "Apple",
            "Amazon",
            "Oracle",
            "Adobe",
            "Cisco",
            "VMware",
            "Linux",
            "Apache",
            "Mozilla",
            "OpenSSL",
            "Docker",
            "Kubernetes",
            "Jenkins",
            "GitLab",
            "GitHub",
            "Atlassian",
            "Elastic",
            "MongoDB",
            "PostgreSQL",
            "MySQL",
            "Redis",
            "nginx",
            "Node.js",
            "Python",
            "Java",
            "PHP",
            "Ruby",
            "WordPress",
            "Drupal",
            "Joomla",
        }
    )

    # Infrastructure tags that increase priority
    infrastructure_tags: Set[str] = field(
        default_factory=lambda: {
            "network",
            "infrastructure",
            "remote",
            "authentication",
            "authorization",
            "cryptography",
            "kernel",
            "privilege-escalation",
            "code-execution",
            "sql-injection",
            "xss",
            "xxe",
            "deserialization",
            "path-traversal",
            "file-upload",
            "command-injection",
            "ldap-injection",
            "memory-corruption",
            "buffer-overflow",
            "use-after-free",
            "race-condition",
        }
    )

    # Exploitation status keywords
    exploitation_keywords: Set[str] = field(
        default_factory=lambda: {
            "exploited",
            "exploitation",
            "in-the-wild",
            "active",
            "ransomware",
            "malware",
            "botnet",
            "0day",
            "zero-day",
            "proof-of-concept",
            "poc",
            "metasploit",
            "exploit-db",
        }
    )

    # Data quality thresholds
    min_description_words: int = 10
    min_affected_products: int = 0
    warn_if_no_references: bool = True
    warn_if_no_cvss: bool = True
    warn_if_no_epss: bool = False  # EPSS might not be available for all CVEs

    # Deduplication settings
    enable_deduplication: bool = True
    dedup_window_days: int = 7

    # Enrichment timeouts
    epss_timeout_seconds: float = 30.0
    github_timeout_seconds: float = 60.0
    max_enrichment_retries: int = 3

    # Batch processing limits
    max_batch_size: int = 1000
    max_vulnerabilities_per_briefing: int = 50

    # Cache settings
    cache_ttl_days: int = 10
    cache_max_size_mb: int = 500

    # Metrics and monitoring
    track_quality_metrics: bool = True
    quality_score_weights: Dict[str, float] = field(
        default_factory=lambda: {
            "has_cvss": 0.2,
            "has_epss": 0.15,
            "has_references": 0.15,
            "has_affected_products": 0.1,
            "has_cpe": 0.1,
            "description_quality": 0.1,
            "has_attack_vector": 0.1,
            "is_recent": 0.1,
        }
    )

    @classmethod
    def from_dict(cls, config_dict: Dict) -> "DataQualityConfig":
        """Create configuration from dictionary."""
        # Convert lists to sets where needed
        if "allowed_severities" in config_dict:
            config_dict["allowed_severities"] = set(config_dict["allowed_severities"])
        if "blocked_vendors" in config_dict:
            config_dict["blocked_vendors"] = set(config_dict["blocked_vendors"])
        if "blocked_products" in config_dict:
            config_dict["blocked_products"] = set(config_dict["blocked_products"])
        if "priority_vendors" in config_dict:
            config_dict["priority_vendors"] = set(config_dict["priority_vendors"])
        if "infrastructure_tags" in config_dict:
            config_dict["infrastructure_tags"] = set(config_dict["infrastructure_tags"])
        if "exploitation_keywords" in config_dict:
            config_dict["exploitation_keywords"] = set(
                config_dict["exploitation_keywords"]
            )

        return cls(**config_dict)

    def to_dict(self) -> Dict:
        """Convert configuration to dictionary."""
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, set):
                result[key] = list(value)
            else:
                result[key] = value
        return result

    def validate(self) -> List[str]:
        """Validate configuration settings.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Validate severity
        if self.min_severity not in self.allowed_severities:
            errors.append(
                f"min_severity '{self.min_severity}' not in allowed_severities"
            )

        # Validate score ranges
        if not 0 <= self.min_cvss_score <= 10:
            errors.append("min_cvss_score must be between 0 and 10")
        if not 0 <= self.max_cvss_score <= 10:
            errors.append("max_cvss_score must be between 0 and 10")
        if self.min_cvss_score > self.max_cvss_score:
            errors.append("min_cvss_score cannot be greater than max_cvss_score")

        if not 0 <= self.min_epss_score <= 1:
            errors.append("min_epss_score must be between 0 and 1")
        if not 0 <= self.max_epss_score <= 1:
            errors.append("max_epss_score must be between 0 and 1")
        if self.min_epss_score > self.max_epss_score:
            errors.append("min_epss_score cannot be greater than max_epss_score")

        if not 0 <= self.min_risk_score <= 100:
            errors.append("min_risk_score must be between 0 and 100")
        if not 0 <= self.max_risk_score <= 100:
            errors.append("max_risk_score must be between 0 and 100")
        if self.min_risk_score > self.max_risk_score:
            errors.append("min_risk_score cannot be greater than max_risk_score")

        # Validate year range
        if self.min_year > self.max_year:
            errors.append("min_year cannot be greater than max_year")

        # Validate quality score weights
        total_weight = sum(self.quality_score_weights.values())
        if abs(total_weight - 1.0) > 0.01:  # Allow small floating point errors
            errors.append(
                f"quality_score_weights must sum to 1.0 (current sum: {total_weight})"
            )

        return errors
