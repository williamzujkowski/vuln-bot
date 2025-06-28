"""Data models for vulnerability information."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class SeverityLevel(str, Enum):
    """CVSS severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


class ExploitationStatus(str, Enum):
    """Exploitation status for vulnerabilities."""

    ACTIVE = "ACTIVE"
    POC = "POC"
    WEAPONIZED = "WEAPONIZED"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class CVSSMetric(BaseModel):
    """CVSS metric data."""

    version: str
    vector_string: str
    base_score: float = Field(ge=0.0, le=10.0)
    base_severity: SeverityLevel
    exploitability_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    impact_score: Optional[float] = Field(None, ge=0.0, le=10.0)


class EPSSScore(BaseModel):
    """EPSS (Exploit Prediction Scoring System) data."""

    score: float = Field(ge=0.0, le=1.0)
    percentile: float = Field(ge=0.0, le=100.0)
    date: datetime

    @field_validator("score", "percentile", mode="before")
    @classmethod
    def round_values(cls, v):
        """Round to 4 decimal places."""
        return round(v, 4)


class Reference(BaseModel):
    """External reference for a vulnerability."""

    url: str
    source: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class CPEMatch(BaseModel):
    """CPE (Common Platform Enumeration) match data."""

    cpe23_uri: str
    cpe_name: Optional[str] = None
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None


class ATTACKTechnique(BaseModel):
    """MITRE ATT&CK technique mapping."""

    technique_id: str
    technique_name: str
    tactic: Optional[str] = None


class VulnerabilitySource(BaseModel):
    """Source information for vulnerability data."""

    name: str
    url: Optional[str] = None
    last_modified: Optional[datetime] = None


class Vulnerability(BaseModel):
    """Complete vulnerability data model."""

    # Core identifiers
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    title: str
    description: str

    # Dates
    published_date: datetime
    last_modified_date: datetime

    # Scoring
    cvss_metrics: List[CVSSMetric] = Field(default_factory=list)
    epss_score: Optional[EPSSScore] = None
    risk_score: int = Field(ge=0, le=100, default=0)

    # Severity and exploitation
    severity: SeverityLevel
    exploitation_status: ExploitationStatus = ExploitationStatus.UNKNOWN

    # Affected systems
    cpe_matches: List[CPEMatch] = Field(default_factory=list)
    affected_vendors: List[str] = Field(default_factory=list)
    affected_products: List[str] = Field(default_factory=list)

    # References and mappings
    references: List[Reference] = Field(default_factory=list)
    attack_techniques: List[ATTACKTechnique] = Field(default_factory=list)

    # Metadata
    tags: List[str] = Field(default_factory=list)
    sources: List[VulnerabilitySource] = Field(default_factory=list)

    # Additional fields for filtering
    requires_user_interaction: Optional[bool] = None
    requires_privileges: Optional[str] = None
    attack_vector: Optional[str] = None

    # Data quality score (calculated during validation)
    quality_score: Optional[float] = None

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat()}

    @property
    def cvss_base_score(self) -> Optional[float]:
        """Get the highest CVSS base score."""
        if not self.cvss_metrics:
            return None
        return max(metric.base_score for metric in self.cvss_metrics)

    @property
    def epss_probability(self) -> Optional[float]:
        """Get EPSS probability as percentage."""
        if not self.epss_score:
            return None
        return round(self.epss_score.score * 100, 2)

    @property
    def cvss_vector(self) -> Optional[str]:
        """Get the CVSS vector string from the highest scored metric."""
        if not self.cvss_metrics:
            return None
        # Return vector from the metric with highest base score
        highest_metric = max(self.cvss_metrics, key=lambda m: m.base_score)
        return highest_metric.vector_string

    @property
    def is_exploited(self) -> bool:
        """Check if vulnerability is being exploited."""
        return self.exploitation_status in [
            ExploitationStatus.ACTIVE,
            ExploitationStatus.WEAPONIZED,
        ]

    def to_summary_dict(self) -> Dict[str, Any]:
        """Convert to summary dictionary for index."""
        return {
            "cveId": self.cve_id,
            "title": self.title,
            "severity": self.severity.value,
            "cvssScore": self.cvss_base_score,
            "epssScore": self.epss_probability,
            "riskScore": self.risk_score,
            "publishedDate": self.published_date.isoformat(),
            "exploitationStatus": self.exploitation_status.value,
            "vendors": self.affected_vendors[:5],  # Top 5 vendors
            "tags": self.tags,
        }

    def to_detail_dict(self) -> Dict[str, Any]:
        """Convert to detailed dictionary for API."""
        return {
            "cveId": self.cve_id,
            "title": self.title,
            "description": self.description,
            "publishedDate": self.published_date.isoformat(),
            "lastModifiedDate": self.last_modified_date.isoformat(),
            "severity": self.severity.value,
            "cvssMetrics": [
                {
                    "version": m.version,
                    "vectorString": m.vector_string,
                    "baseScore": m.base_score,
                    "baseSeverity": m.base_severity.value,
                }
                for m in self.cvss_metrics
            ],
            "epss": {
                "score": self.epss_score.score,
                "percentile": self.epss_score.percentile,
            }
            if self.epss_score
            else None,
            "riskScore": self.risk_score,
            "exploitationStatus": self.exploitation_status.value,
            "affectedSystems": {
                "cpeMatches": [
                    {
                        "cpe23Uri": cpe.cpe23_uri,
                        "versionRange": {
                            k: v
                            for k, v in {
                                "versionStartIncluding": cpe.version_start_including,
                                "versionStartExcluding": cpe.version_start_excluding,
                                "versionEndIncluding": cpe.version_end_including,
                                "versionEndExcluding": cpe.version_end_excluding,
                            }.items()
                            if v
                        }
                        if any(
                            [
                                cpe.version_start_including,
                                cpe.version_start_excluding,
                                cpe.version_end_including,
                                cpe.version_end_excluding,
                            ]
                        )
                        else None,
                    }
                    for cpe in self.cpe_matches
                ],
                "vendors": self.affected_vendors,
                "products": self.affected_products,
            },
            "references": [
                {"url": ref.url, "source": ref.source, "tags": ref.tags}
                for ref in self.references
            ],
            "attackTechniques": [
                {
                    "techniqueId": tech.technique_id,
                    "techniqueName": tech.technique_name,
                    "tactic": tech.tactic,
                }
                for tech in self.attack_techniques
            ],
            "metadata": {
                "tags": self.tags,
                "requiresUserInteraction": self.requires_user_interaction,
                "requiresPrivileges": self.requires_privileges,
                "attackVector": self.attack_vector,
                "sources": [
                    {
                        "name": src.name,
                        "url": src.url,
                        "lastModified": src.last_modified.isoformat()
                        if src.last_modified
                        else None,
                    }
                    for src in self.sources
                ],
            },
        }


class VulnerabilityBatch(BaseModel):
    """Batch of vulnerabilities for processing."""

    vulnerabilities: List[Vulnerability]
    metadata: Dict[str, Any] = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def count(self) -> int:
        """Get number of vulnerabilities in batch."""
        return len(self.vulnerabilities)

    def filter_by_severity(self, min_severity: SeverityLevel) -> List[Vulnerability]:
        """Filter vulnerabilities by minimum severity."""
        severity_order = {
            SeverityLevel.NONE: 0,
            SeverityLevel.LOW: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.HIGH: 3,
            SeverityLevel.CRITICAL: 4,
        }
        min_level = severity_order[min_severity]
        return [
            v for v in self.vulnerabilities if severity_order[v.severity] >= min_level
        ]

    def filter_by_risk_score(self, min_score: int) -> List[Vulnerability]:
        """Filter vulnerabilities by minimum risk score."""
        return [v for v in self.vulnerabilities if v.risk_score >= min_score]

    def sort_by_risk(self) -> List[Vulnerability]:
        """Sort vulnerabilities by risk score (descending)."""
        return sorted(
            self.vulnerabilities,
            key=lambda v: (v.risk_score, v.epss_probability or 0),
            reverse=True,
        )
