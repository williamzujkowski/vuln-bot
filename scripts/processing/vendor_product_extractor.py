"""Enhanced vendor and product extraction utility for CVE data."""

import re
from typing import Dict, List, Tuple

import structlog


class VendorProductExtractor:
    """Enhanced extraction of vendor and product information from CVE data."""

    def __init__(self):
        """Initialize the extractor."""
        self.logger = structlog.get_logger(self.__class__.__name__)

        # Common vendor mappings for normalization
        self.vendor_mappings = {
            "microsoft": "Microsoft",
            "microsoft corporation": "Microsoft",
            "ms": "Microsoft",
            "apple": "Apple",
            "apple inc": "Apple",
            "google": "Google",
            "google llc": "Google",
            "adobe": "Adobe",
            "adobe systems": "Adobe",
            "oracle": "Oracle",
            "oracle corporation": "Oracle",
            "cisco": "Cisco",
            "cisco systems": "Cisco",
            "vmware": "VMware",
            "vmware inc": "VMware",
            "linux": "Linux",
            "red hat": "Red Hat",
            "redhat": "Red Hat",
            "canonical": "Canonical",
            "mozilla": "Mozilla",
            "mozilla foundation": "Mozilla",
            "ibm": "IBM",
            "intel": "Intel",
            "intel corporation": "Intel",
            "nvidia": "NVIDIA",
            "nvidia corporation": "NVIDIA",
            "apache": "Apache",
            "apache software foundation": "Apache",
            "wordpress": "WordPress",
            "automattic": "WordPress",
            "drupal": "Drupal",
            "drupal association": "Drupal",
            "joomla": "Joomla",
            "postgresql": "PostgreSQL",
            "mysql": "MySQL",
            "mongodb": "MongoDB",
            "elastic": "Elastic",
            "elasticsearch": "Elastic",
            "jenkins": "Jenkins",
            "atlassian": "Atlassian",
            "docker": "Docker",
            "kubernetes": "Kubernetes",
            "golang": "Go",
            "python": "Python",
            "node.js": "Node.js",
            "nodejs": "Node.js",
            "php": "PHP",
            "ruby": "Ruby",
            "npm": "npm",
            "yarn": "Yarn",
            "composer": "Composer",
            "pip": "PyPI",
            "pypi": "PyPI",
        }

        # Patterns for extracting vendor/product from descriptions
        self.description_patterns = [
            # Microsoft products
            (
                r"\b(microsoft)\s+(outlook|office|windows|exchange|sharepoint|teams|edge|azure)\b",
                "Microsoft",
                r"\2",
            ),
            (r"\b(ms)\s+(office|outlook|word|excel|powerpoint)\b", "Microsoft", r"\2"),
            (
                r"\b(windows)\s+(\d+|server|vista|xp|7|8|10|11)\b",
                "Microsoft",
                "Windows",
            ),
            (r"\b(internet explorer|ie)\s*(\d+)?\b", "Microsoft", "Internet Explorer"),
            # Apple products
            (r"\b(apple)\s+(safari|ios|macos|watchos|tvos)\b", "Apple", r"\2"),
            (r"\b(safari)\s+(\d+(?:\.\d+)*)\b", "Apple", "Safari"),
            (r"\b(ios)\s+(\d+(?:\.\d+)*)\b", "Apple", "iOS"),
            (r"\b(macos)\s+(\w+)\b", "Apple", "macOS"),
            # Google products
            (r"\b(google)\s+(chrome|android|firebase|cloud)\b", "Google", r"\2"),
            (r"\b(chrome)\s+(\d+(?:\.\d+)*)\b", "Google", "Chrome"),
            (r"\b(android)\s+(\d+(?:\.\d+)*)\b", "Google", "Android"),
            # Adobe products
            (
                r"\b(adobe)\s+(flash|reader|acrobat|photoshop|illustrator)\b",
                "Adobe",
                r"\2",
            ),
            (r"\b(flash player)\b", "Adobe", "Flash Player"),
            # Oracle products
            (r"\b(oracle)\s+(database|weblogic|java|mysql)\b", "Oracle", r"\2"),
            (r"\b(java)\s+(se|ee|runtime|jre|jdk)\b", "Oracle", "Java"),
            # Cisco products
            (r"\b(cisco)\s+(ios|asa|firepower|webex)\b", "Cisco", r"\2"),
            # VMware products
            (r"\b(vmware)\s+(vsphere|vcenter|workstation|fusion)\b", "VMware", r"\2"),
            # Linux distributions
            (
                r"\b(red hat|redhat)\s+(enterprise|linux|rhel)\b",
                "Red Hat",
                "Red Hat Enterprise Linux",
            ),
            (r"\b(ubuntu)\s+(\d+\.\d+)\b", "Canonical", "Ubuntu"),
            (r"\b(debian)\s+(\d+)\b", "Debian", "Debian"),
            (r"\b(centos)\s+(\d+)\b", "CentOS", "CentOS"),
            (r"\b(suse)\s+(linux|enterprise)\b", "SUSE", "SUSE Linux"),
            # Web browsers
            (r"\b(firefox)\s+(\d+(?:\.\d+)*)\b", "Mozilla", "Firefox"),
            (r"\b(mozilla)\s+(firefox)\b", "Mozilla", "Firefox"),
            # Web frameworks and applications
            (r"\b(wordpress)\b", "WordPress", "WordPress"),
            (r"\b(drupal)\s+(\d+(?:\.\d+)*)\b", "Drupal", "Drupal"),
            (r"\b(joomla)\s+(\d+(?:\.\d+)*)\b", "Joomla", "Joomla"),
            # Databases
            (r"\b(postgresql)\s+(\d+(?:\.\d+)*)\b", "PostgreSQL", "PostgreSQL"),
            (r"\b(mysql)\s+(\d+(?:\.\d+)*)\b", "MySQL", "MySQL"),
            (r"\b(mongodb)\s+(\d+(?:\.\d+)*)\b", "MongoDB", "MongoDB"),
            (r"\b(elasticsearch)\b", "Elastic", "Elasticsearch"),
            # Development tools
            (r"\b(jenkins)\s+(\d+(?:\.\d+)*)\b", "Jenkins", "Jenkins"),
            (r"\b(docker|docker engine)\b", "Docker", "Docker"),
            (r"\b(kubernetes|k8s)\b", "Kubernetes", "Kubernetes"),
            # Programming languages/runtimes
            (r"\b(node\.?js)\s+(\d+(?:\.\d+)*)\b", "Node.js", "Node.js"),
            (r"\b(python)\s+(\d+(?:\.\d+)*)\b", "Python", "Python"),
            (r"\b(php)\s+(\d+(?:\.\d+)*)\b", "PHP", "PHP"),
            (r"\b(ruby)\s+(\d+(?:\.\d+)*)\b", "Ruby", "Ruby"),
            (r"\b(go|golang)\s+(\d+(?:\.\d+)*)\b", "Go", "Go"),
            # Apache specific improvements
            (r"\b(apache)\s+(http\s+server)\b", "Apache", "Apache HTTP Server"),
            # NOTE: Removed overly broad generic pattern that was catching common words
            # like "The", "Web", "File" from descriptions. Structured data from
            # affected/CPE fields should be the primary source.
        ]

    def extract_vendors_products(
        self, cve_data: Dict, description: str = "", title: str = ""
    ) -> Tuple[List[str], List[str]]:
        """Extract vendor and product information from CVE data.

        Args:
            cve_data: Full CVE data structure
            description: CVE description text
            title: CVE title text

        Returns:
            Tuple of (vendors, products) lists
        """
        vendors = set()
        products = set()

        # Method 1: Extract from structured affected data
        affected_vendors, affected_products = self._extract_from_affected_data(cve_data)
        vendors.update(affected_vendors)
        products.update(affected_products)

        # Method 2: Extract from CPE data (if available)
        cpe_vendors, cpe_products = self._extract_from_cpe_data(cve_data)
        vendors.update(cpe_vendors)
        products.update(cpe_products)

        # Method 3: Extract from description and title using patterns
        text_vendors, text_products = self._extract_from_text(description + " " + title)
        vendors.update(text_vendors)
        products.update(text_products)

        # Method 4: Extract from references
        ref_vendors, ref_products = self._extract_from_references(cve_data)
        vendors.update(ref_vendors)
        products.update(ref_products)

        # Normalize and filter results
        normalized_vendors = self._normalize_vendors(list(vendors))
        normalized_products = self._normalize_products(list(products))

        self.logger.debug(
            "Extracted vendor/product data",
            cve_id=cve_data.get("cveMetadata", {}).get("cveId", "unknown"),
            vendors=normalized_vendors,
            products=normalized_products,
        )

        return normalized_vendors, normalized_products

    def _extract_from_affected_data(
        self, cve_data: Dict
    ) -> Tuple[List[str], List[str]]:
        """Extract from structured affected data in CVE."""
        vendors = set()
        products = set()

        containers = cve_data.get("containers", {})
        cna = containers.get("cna", {})

        for affected in cna.get("affected", []):
            vendor = affected.get("vendor", "").strip()
            if vendor and vendor != "*" and len(vendor) > 1:
                vendors.add(vendor.lower())

            product = affected.get("product", "").strip()
            if product and product != "*" and len(product) > 1:
                products.add(product.lower())

        return list(vendors), list(products)

    def _extract_from_cpe_data(self, cve_data: Dict) -> Tuple[List[str], List[str]]:
        """Extract from CPE (Common Platform Enumeration) data."""
        vendors = set()
        products = set()

        # Look for CPE data in configurations (NVD format)
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe_name = cpe_match.get("criteria", "")
                    if cpe_name:
                        cpe_vendors, cpe_products = self._parse_cpe_string(cpe_name)
                        vendors.update(cpe_vendors)
                        products.update(cpe_products)

        return list(vendors), list(products)

    def _parse_cpe_string(self, cpe_string: str) -> Tuple[List[str], List[str]]:
        """Parse CPE string to extract vendor and product."""
        vendors = []
        products = []

        # CPE format: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        parts = cpe_string.split(":")
        if len(parts) >= 5:
            vendor_part = parts[3].replace("_", " ").strip()
            product_part = parts[4].replace("_", " ").strip()

            if vendor_part and vendor_part != "*":
                vendors.append(vendor_part.lower())
            if product_part and product_part != "*":
                products.append(product_part.lower())

        return vendors, products

    def _extract_from_text(self, text: str) -> Tuple[List[str], List[str]]:
        """Extract vendor/product from description text using patterns."""
        vendors = set()
        products = set()

        text_lower = text.lower()

        for pattern, vendor_template, product_template in self.description_patterns:
            matches = re.finditer(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                try:
                    # Process vendor
                    if isinstance(
                        vendor_template, str
                    ) and not vendor_template.startswith("\\"):
                        vendor = vendor_template
                    else:
                        vendor = match.expand(vendor_template)

                    # Process product
                    if isinstance(
                        product_template, str
                    ) and not product_template.startswith("\\"):
                        product = product_template
                    else:
                        product = match.expand(product_template)

                    # Filter out common false positives
                    if (
                        vendor
                        and len(vendor) > 1
                        and not vendor.lower().startswith("vulnerability")
                    ):
                        vendors.add(vendor.lower())
                    if (
                        product
                        and len(product) > 1
                        and not product.lower().startswith("vulnerability")
                    ):
                        products.add(product.lower())

                except Exception:
                    # Skip malformed patterns
                    continue

        return list(vendors), list(products)

    def _extract_from_references(self, cve_data: Dict) -> Tuple[List[str], List[str]]:
        """Extract vendor/product from reference URLs."""
        vendors = set()
        products = set()

        containers = cve_data.get("containers", {})
        cna = containers.get("cna", {})

        for ref in cna.get("references", []):
            url = ref.get("url", "").lower()

            # Extract from domain names
            domain_patterns = [
                (r"microsoft\.com", "microsoft"),
                (r"apple\.com", "apple"),
                (r"google\.com", "google"),
                (r"adobe\.com", "adobe"),
                (r"oracle\.com", "oracle"),
                (r"cisco\.com", "cisco"),
                (r"vmware\.com", "vmware"),
                (r"redhat\.com", "red hat"),
                (r"canonical\.com", "canonical"),
                (r"mozilla\.org", "mozilla"),
                (r"wordpress\.org", "wordpress"),
                (r"drupal\.org", "drupal"),
                (r"jenkins\.io", "jenkins"),
                (r"docker\.com", "docker"),
                (r"nodejs\.org", "node.js"),
                (r"python\.org", "python"),
                (r"php\.net", "php"),
                (r"ruby-lang\.org", "ruby"),
                (r"golang\.org", "go"),
            ]

            for pattern, vendor in domain_patterns:
                if re.search(pattern, url):
                    vendors.add(vendor)
                    break

        return list(vendors), list(products)

    def _normalize_vendors(self, vendors: List[str]) -> List[str]:
        """Normalize vendor names, preserving multi-word names and special characters."""
        normalized = []
        for vendor in vendors:
            # Preserve original spacing and special characters
            vendor_clean = vendor.strip()

            # Skip empty or very short vendors
            if len(vendor_clean) < 2:
                continue

            # Skip placeholder values
            if vendor_clean.lower() in ["n/a", "na", "none", "unknown", "unspecified", "tbd", "pending", "*"]:
                continue

            # Skip if it's all digits
            if vendor_clean.isdigit():
                continue

            # Skip if it contains no letters
            if not any(c.isalpha() for c in vendor_clean):
                continue

            # Apply vendor mappings for known vendors
            vendor_lower = vendor_clean.lower()
            if vendor_lower in self.vendor_mappings:
                normalized_vendor = self.vendor_mappings[vendor_lower]
                if normalized_vendor not in normalized:
                    normalized.append(normalized_vendor)
            else:
                # Preserve original capitalization and spacing for multi-word names
                # Only capitalize if all lowercase
                if vendor_clean.islower():
                    capitalized = " ".join(
                        word.capitalize() for word in vendor_clean.split()
                    )
                else:
                    # Preserve existing capitalization (e.g., "IBM", "eBay", "jQuery")
                    capitalized = vendor_clean

                if capitalized not in normalized:
                    normalized.append(capitalized)

        return sorted(normalized)

    def _normalize_products(self, products: List[str]) -> List[str]:
        """Normalize product names, preserving multi-word names and special characters."""
        normalized = []
        for product in products:
            # Preserve original spacing and special characters
            product_clean = product.strip()

            # Skip empty or very short products
            if len(product_clean) < 2:
                continue

            # Skip placeholder values
            if product_clean.lower() in ["n/a", "na", "none", "unknown", "unspecified", "tbd", "pending", "*"]:
                continue

            # Skip if it's all digits
            if product_clean.isdigit():
                continue

            # Skip if it contains no letters
            if not any(c.isalpha() for c in product_clean):
                continue

            # Preserve original capitalization and spacing for multi-word names
            # Only capitalize if all lowercase
            if product_clean.islower():
                capitalized = " ".join(
                    word.capitalize() for word in product_clean.split()
                )
            else:
                # Preserve existing capitalization (e.g., "iOS", "macOS", "WordPress")
                capitalized = product_clean

            if capitalized not in normalized:
                normalized.append(capitalized)

        return sorted(normalized)
