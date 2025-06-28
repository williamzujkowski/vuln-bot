"""Data normalization pipeline for vulnerability data from multiple sources."""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import structlog
from dateutil import parser as date_parser

from scripts.models import (
    ExploitationStatus,
    Reference,
    SeverityLevel,
    Vulnerability,
    VulnerabilitySource,
)


class VulnerabilityNormalizer:
    """Normalize vulnerability data from different sources into a common format."""

    # Patterns for extracting CVE IDs
    CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
    
    # Keywords for exploitation detection
    EXPLOITATION_KEYWORDS = {
        "active": ["actively exploited", "in the wild", "active exploitation", "ongoing attacks"],
        "weaponized": ["weaponized", "exploit kit", "ransomware", "malware"],
        "poc": ["proof of concept", "poc", "exploit code", "demonstration"],
    }
    
    # Severity mappings from different sources
    SEVERITY_MAPPINGS = {
        # Common severity terms
        "critical": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "moderate": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
        "none": SeverityLevel.NONE,
        "informational": SeverityLevel.NONE,
        # Numeric mappings (for scores)
        "9-10": SeverityLevel.CRITICAL,
        "7-8.9": SeverityLevel.HIGH,
        "4-6.9": SeverityLevel.MEDIUM,
        "0.1-3.9": SeverityLevel.LOW,
        "0": SeverityLevel.NONE,
    }
    
    # Tag extraction patterns
    TAG_PATTERNS = {
        "authentication": re.compile(r"\b(auth|authentication|login|credential)\b", re.I),
        "remote": re.compile(r"\b(remote|network)\b", re.I),
        "privilege_escalation": re.compile(r"\b(privilege|escalat|root|admin)\b", re.I),
        "injection": re.compile(r"\b(inject|sqli|xss|xxe)\b", re.I),
        "rce": re.compile(r"\b(rce|remote code|command execution)\b", re.I),
        "dos": re.compile(r"\b(dos|denial of service|crash)\b", re.I),
        "bypass": re.compile(r"\b(bypass|circumvent)\b", re.I),
        "memory": re.compile(r"\b(buffer|overflow|memory|heap|stack)\b", re.I),
    }

    def __init__(self):
        """Initialize normalizer."""
        self.logger = structlog.get_logger(self.__class__.__name__)

    def normalize_cve_id(self, cve_id: str) -> Optional[str]:
        """Normalize and validate CVE ID format.
        
        Args:
            cve_id: Raw CVE ID string
            
        Returns:
            Normalized CVE ID or None if invalid
        """
        # Extract CVE ID from string
        match = self.CVE_PATTERN.search(cve_id)
        if match:
            return match.group(0).upper()
        return None

    def detect_exploitation_status(self, text: str) -> ExploitationStatus:
        """Detect exploitation status from text.
        
        Args:
            text: Text to analyze (description, references, etc.)
            
        Returns:
            Detected exploitation status
        """
        text_lower = text.lower()
        
        # Check for exploitation keywords
        for status, keywords in self.EXPLOITATION_KEYWORDS.items():
            if any(keyword in text_lower for keyword in keywords):
                if status == "active":
                    return ExploitationStatus.ACTIVE
                elif status == "weaponized":
                    return ExploitationStatus.WEAPONIZED
                elif status == "poc":
                    return ExploitationStatus.POC
        
        return ExploitationStatus.UNKNOWN

    def normalize_severity(self, severity_value: Any) -> SeverityLevel:
        """Normalize severity from various formats.
        
        Args:
            severity_value: Severity in various formats
            
        Returns:
            Normalized severity level
        """
        if isinstance(severity_value, str):
            severity_lower = severity_value.lower().strip()
            
            # Direct mapping
            if severity_lower in self.SEVERITY_MAPPINGS:
                return self.SEVERITY_MAPPINGS[severity_lower]
            
            # Check numeric score ranges
            try:
                score = float(severity_lower)
                if score >= 9.0:
                    return SeverityLevel.CRITICAL
                elif score >= 7.0:
                    return SeverityLevel.HIGH
                elif score >= 4.0:
                    return SeverityLevel.MEDIUM
                elif score > 0.0:
                    return SeverityLevel.LOW
                else:
                    return SeverityLevel.NONE
            except ValueError:
                pass
        
        elif isinstance(severity_value, (int, float)):
            if severity_value >= 9.0:
                return SeverityLevel.CRITICAL
            elif severity_value >= 7.0:
                return SeverityLevel.HIGH
            elif severity_value >= 4.0:
                return SeverityLevel.MEDIUM
            elif severity_value > 0.0:
                return SeverityLevel.LOW
            else:
                return SeverityLevel.NONE
        
        return SeverityLevel.MEDIUM  # Default

    def extract_tags(self, text: str) -> List[str]:
        """Extract relevant tags from text.
        
        Args:
            text: Text to analyze
            
        Returns:
            List of extracted tags
        """
        tags = set()
        
        for tag, pattern in self.TAG_PATTERNS.items():
            if pattern.search(text):
                tags.add(tag)
        
        return sorted(list(tags))

    def parse_date(self, date_value: Any) -> Optional[datetime]:
        """Parse date from various formats.
        
        Args:
            date_value: Date in various formats
            
        Returns:
            Parsed datetime or None
        """
        if isinstance(date_value, datetime):
            return date_value
        
        if isinstance(date_value, str):
            try:
                return date_parser.parse(date_value)
            except (ValueError, TypeError):
                pass
        
        return None

    def merge_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> Vulnerability:
        """Merge multiple vulnerability records for the same CVE.
        
        Args:
            vulnerabilities: List of vulnerability records to merge
            
        Returns:
            Merged vulnerability record
        """
        if not vulnerabilities:
            raise ValueError("No vulnerabilities to merge")
        
        if len(vulnerabilities) == 1:
            return vulnerabilities[0]
        
        # Start with the first vulnerability
        merged = vulnerabilities[0].copy(deep=True)
        
        for vuln in vulnerabilities[1:]:
            # Update dates to most recent
            if vuln.last_modified_date > merged.last_modified_date:
                merged.last_modified_date = vuln.last_modified_date
            
            # Merge CVSS metrics
            for metric in vuln.cvss_metrics:
                if not any(
                    m.version == metric.version and m.vector_string == metric.vector_string
                    for m in merged.cvss_metrics
                ):
                    merged.cvss_metrics.append(metric)
            
            # Update EPSS if newer
            if vuln.epss_score and (
                not merged.epss_score or vuln.epss_score.date > merged.epss_score.date
            ):
                merged.epss_score = vuln.epss_score
            
            # Update exploitation status to highest level
            if vuln.exploitation_status.value > merged.exploitation_status.value:
                merged.exploitation_status = vuln.exploitation_status
            
            # Merge CPE matches
            existing_cpes = {cpe.cpe23_uri for cpe in merged.cpe_matches}
            for cpe in vuln.cpe_matches:
                if cpe.cpe23_uri not in existing_cpes:
                    merged.cpe_matches.append(cpe)
            
            # Merge vendors and products
            merged.affected_vendors = sorted(
                list(set(merged.affected_vendors + vuln.affected_vendors))
            )
            merged.affected_products = sorted(
                list(set(merged.affected_products + vuln.affected_products))
            )
            
            # Merge references
            existing_urls = {ref.url for ref in merged.references}
            for ref in vuln.references:
                if ref.url not in existing_urls:
                    merged.references.append(ref)
            
            # Merge tags
            merged.tags = sorted(list(set(merged.tags + vuln.tags)))
            
            # Add sources
            merged.sources.extend(vuln.sources)
        
        return merged

    def normalize_github_advisory(self, advisory: Dict[str, Any]) -> Optional[Vulnerability]:
        """Normalize GitHub Security Advisory data.
        
        Args:
            advisory: Raw GitHub advisory data
            
        Returns:
            Normalized vulnerability or None
        """
        try:
            # Extract CVE ID
            cve_id = None
            identifiers = advisory.get("identifiers", [])
            for ident in identifiers:
                if ident.get("type") == "CVE":
                    cve_id = self.normalize_cve_id(ident.get("value", ""))
                    break
            
            if not cve_id:
                # Skip non-CVE advisories for now
                return None
            
            # Parse dates
            published_date = self.parse_date(advisory.get("published_at"))
            updated_date = self.parse_date(advisory.get("updated_at"))
            
            if not published_date:
                published_date = datetime.utcnow()
            if not updated_date:
                updated_date = published_date
            
            # Extract severity
            severity = self.normalize_severity(advisory.get("severity", "medium"))
            
            # Extract description
            summary = advisory.get("summary", "")
            description = advisory.get("description", summary)
            
            # Extract tags from description
            tags = self.extract_tags(description)
            
            # Check for exploitation
            exploitation_status = self.detect_exploitation_status(description)
            
            # Extract affected packages
            affected_vendors = set()
            affected_products = set()
            
            vulnerabilities = advisory.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                package = vuln.get("package", {})
                ecosystem = package.get("ecosystem", "")
                name = package.get("name", "")
                
                if ecosystem:
                    affected_vendors.add(ecosystem.lower())
                if name:
                    affected_products.add(name.lower())
            
            # Create references
            references = [
                Reference(
                    url=advisory.get("html_url", ""),
                    source="GitHub Advisory",
                    tags=["advisory"],
                )
            ]
            
            for ref in advisory.get("references", []):
                references.append(
                    Reference(
                        url=ref.get("url", ""),
                        source="GitHub Advisory",
                    )
                )
            
            # Create vulnerability
            vuln = Vulnerability(
                cve_id=cve_id,
                title=f"{cve_id}: {summary[:100]}",
                description=description,
                published_date=published_date,
                last_modified_date=updated_date,
                severity=severity,
                exploitation_status=exploitation_status,
                affected_vendors=sorted(list(affected_vendors)),
                affected_products=sorted(list(affected_products)),
                references=references,
                tags=tags,
                sources=[
                    VulnerabilitySource(
                        name="GitHub Advisory",
                        url=advisory.get("html_url", ""),
                        last_modified=updated_date,
                    )
                ],
            )
            
            return vuln
            
        except Exception as e:
            self.logger.error(
                "Failed to normalize GitHub advisory",
                error=str(e),
                advisory_id=advisory.get("ghsa_id"),
            )
            return None

    def deduplicate_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
    ) -> List[Vulnerability]:
        """Deduplicate vulnerabilities by CVE ID, merging data from multiple sources.
        
        Args:
            vulnerabilities: List of vulnerabilities to deduplicate
            
        Returns:
            Deduplicated list of vulnerabilities
        """
        # Group by CVE ID
        cve_groups: Dict[str, List[Vulnerability]] = {}
        
        for vuln in vulnerabilities:
            if vuln.cve_id not in cve_groups:
                cve_groups[vuln.cve_id] = []
            cve_groups[vuln.cve_id].append(vuln)
        
        # Merge duplicates
        deduplicated = []
        for cve_id, group in cve_groups.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                merged = self.merge_vulnerabilities(group)
                self.logger.debug(
                    "Merged duplicate vulnerabilities",
                    cve_id=cve_id,
                    source_count=len(group),
                )
                deduplicated.append(merged)
        
        self.logger.info(
            "Deduplicated vulnerabilities",
            original_count=len(vulnerabilities),
            deduplicated_count=len(deduplicated),
            duplicates_removed=len(vulnerabilities) - len(deduplicated),
        )
        
        return deduplicated