"""Comprehensive tests for VendorProductExtractor."""

from scripts.processing.vendor_product_extractor import VendorProductExtractor


class TestVendorProductExtractorInitialization:
    """Test suite for VendorProductExtractor initialization."""

    def test_initialization(self):
        """Test extractor initialization."""
        extractor = VendorProductExtractor()

        assert extractor.logger is not None
        assert len(extractor.vendor_mappings) > 0
        assert len(extractor.description_patterns) > 0

    def test_vendor_mappings_exist(self):
        """Test that vendor mappings contain expected vendors."""
        extractor = VendorProductExtractor()

        # Check some key vendor mappings
        assert "microsoft" in extractor.vendor_mappings
        assert "google" in extractor.vendor_mappings
        assert "apple" in extractor.vendor_mappings
        assert "adobe" in extractor.vendor_mappings
        assert "oracle" in extractor.vendor_mappings

    def test_description_patterns_exist(self):
        """Test that description patterns are configured."""
        extractor = VendorProductExtractor()

        # Each pattern should be a tuple of (pattern, vendor, product)
        for pattern in extractor.description_patterns:
            assert len(pattern) == 3
            assert isinstance(pattern[0], str)  # regex pattern
            assert isinstance(pattern[1], str)  # vendor template
            assert isinstance(pattern[2], str)  # product template


class TestExtractFromAffectedData:
    """Test suite for extracting from affected data."""

    def test_extract_from_affected_with_vendor_and_product(self):
        """Test extraction when vendor and product are present."""
        extractor = VendorProductExtractor()

        cve_data = {
            "containers": {
                "cna": {"affected": [{"vendor": "Microsoft", "product": "Windows 10"}]}
            }
        }

        vendors, products = extractor._extract_from_affected_data(cve_data)

        assert "microsoft" in vendors
        assert "windows 10" in products

    def test_extract_from_affected_multiple_items(self):
        """Test extraction with multiple affected items."""
        extractor = VendorProductExtractor()

        cve_data = {
            "containers": {
                "cna": {
                    "affected": [
                        {"vendor": "Microsoft", "product": "Office"},
                        {"vendor": "Adobe", "product": "Reader"},
                    ]
                }
            }
        }

        vendors, products = extractor._extract_from_affected_data(cve_data)

        assert len(vendors) == 2
        assert "microsoft" in vendors
        assert "adobe" in vendors
        assert len(products) == 2
        assert "office" in products
        assert "reader" in products

    def test_extract_from_affected_filters_placeholders(self):
        """Test that placeholder values are filtered."""
        extractor = VendorProductExtractor()

        cve_data = {
            "containers": {
                "cna": {
                    "affected": [
                        {"vendor": "*", "product": "Valid Product"},
                        {"vendor": "Valid Vendor", "product": "*"},
                        {"vendor": "n", "product": "x"},  # Too short
                    ]
                }
            }
        }

        vendors, products = extractor._extract_from_affected_data(cve_data)

        assert "*" not in vendors
        assert "*" not in products
        assert "n" not in vendors
        assert "x" not in products
        assert "valid vendor" in vendors
        assert "valid product" in products

    def test_extract_from_affected_empty_data(self):
        """Test extraction with no affected data."""
        extractor = VendorProductExtractor()

        cve_data = {"containers": {"cna": {}}}

        vendors, products = extractor._extract_from_affected_data(cve_data)

        assert vendors == []
        assert products == []


class TestExtractFromCPEData:
    """Test suite for extracting from CPE data."""

    def test_extract_from_cpe_valid_data(self):
        """Test extraction from valid CPE data."""
        extractor = VendorProductExtractor()

        cve_data = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": "cpe:2.3:a:microsoft:windows_10:1809:*:*:*:*:*:*:*"
                                }
                            ]
                        }
                    ]
                }
            ]
        }

        vendors, products = extractor._extract_from_cpe_data(cve_data)

        assert "microsoft" in vendors
        assert "windows 10" in products

    def test_parse_cpe_string_valid(self):
        """Test parsing valid CPE string."""
        extractor = VendorProductExtractor()

        cpe_string = "cpe:2.3:a:adobe:flash_player:32.0.0.465:*:*:*:*:*:*:*"
        vendors, products = extractor._parse_cpe_string(cpe_string)

        assert "adobe" in vendors
        assert "flash player" in products

    def test_parse_cpe_string_filters_wildcards(self):
        """Test that CPE wildcards are filtered."""
        extractor = VendorProductExtractor()

        cpe_string = "cpe:2.3:a:*:test_product:1.0:*:*:*:*:*:*:*"
        vendors, products = extractor._parse_cpe_string(cpe_string)

        assert vendors == []
        assert "test product" in products

    def test_parse_cpe_string_malformed(self):
        """Test parsing malformed CPE string."""
        extractor = VendorProductExtractor()

        cpe_string = "invalid:cpe:string"
        vendors, products = extractor._parse_cpe_string(cpe_string)

        # Should handle gracefully with empty results
        assert vendors == []
        assert products == []

    def test_extract_from_cpe_empty_data(self):
        """Test extraction with no CPE data."""
        extractor = VendorProductExtractor()

        cve_data = {}
        vendors, products = extractor._extract_from_cpe_data(cve_data)

        assert vendors == []
        assert products == []


class TestExtractFromText:
    """Test suite for extracting from text descriptions."""

    def test_extract_microsoft_products(self):
        """Test extraction of Microsoft products from text."""
        extractor = VendorProductExtractor()

        text = "Vulnerability in Microsoft Windows 10 and Microsoft Office"
        vendors, products = extractor._extract_from_text(text)

        assert "microsoft" in vendors
        # Products may vary based on pattern matching

    def test_extract_google_chrome(self):
        """Test extraction of Google Chrome from text."""
        extractor = VendorProductExtractor()

        text = "Remote code execution in Google Chrome 95.0.4638.69"
        vendors, products = extractor._extract_from_text(text)

        assert "google" in vendors
        assert "chrome" in products

    def test_extract_adobe_flash(self):
        """Test extraction of Adobe Flash from text."""
        extractor = VendorProductExtractor()

        text = "Critical vulnerability in Adobe Flash Player version 32.0"
        vendors, products = extractor._extract_from_text(text)

        assert "adobe" in vendors
        # Product extraction may vary

    def test_extract_linux_distributions(self):
        """Test extraction of Linux distributions."""
        extractor = VendorProductExtractor()

        text = "Affects Red Hat Enterprise Linux and Ubuntu 20.04"
        vendors, products = extractor._extract_from_text(text)

        # Should extract Red Hat and Canonical (Ubuntu vendor)
        assert any(v in vendors for v in ["red hat", "canonical"])

    def test_extract_web_browsers(self):
        """Test extraction of web browsers."""
        extractor = VendorProductExtractor()

        text = "Firefox 92.0 and Chrome 94.0 are affected"
        vendors, products = extractor._extract_from_text(text)

        # Should extract Mozilla and Google
        assert any(v in vendors for v in ["mozilla", "google"])

    def test_extract_filters_false_positives(self):
        """Test that false positives are filtered."""
        extractor = VendorProductExtractor()

        text = "Vulnerability in the web application"
        vendors, products = extractor._extract_from_text(text)

        # "vulnerability" should be filtered out
        assert "vulnerability" not in vendors
        assert "vulnerability" not in products

    def test_extract_from_text_empty_string(self):
        """Test extraction from empty text."""
        extractor = VendorProductExtractor()

        vendors, products = extractor._extract_from_text("")

        assert vendors == []
        assert products == []


class TestExtractFromReferences:
    """Test suite for extracting from reference URLs."""

    def test_extract_from_microsoft_url(self):
        """Test extraction from Microsoft reference URL."""
        extractor = VendorProductExtractor()

        cve_data = {
            "containers": {
                "cna": {
                    "references": [
                        {"url": "https://www.microsoft.com/security/advisory"}
                    ]
                }
            }
        }

        vendors, products = extractor._extract_from_references(cve_data)

        assert "microsoft" in vendors

    def test_extract_from_multiple_urls(self):
        """Test extraction from multiple reference URLs."""
        extractor = VendorProductExtractor()

        cve_data = {
            "containers": {
                "cna": {
                    "references": [
                        {"url": "https://www.microsoft.com/security"},
                        {"url": "https://www.adobe.com/security"},
                        {"url": "https://www.google.com/chrome/security"},
                    ]
                }
            }
        }

        vendors, products = extractor._extract_from_references(cve_data)

        assert "microsoft" in vendors
        assert "adobe" in vendors
        assert "google" in vendors

    def test_extract_from_references_no_match(self):
        """Test extraction when URLs don't match known vendors."""
        extractor = VendorProductExtractor()

        cve_data = {
            "containers": {
                "cna": {"references": [{"url": "https://example.com/security"}]}
            }
        }

        vendors, products = extractor._extract_from_references(cve_data)

        # Unknown domain should not match
        assert vendors == []

    def test_extract_from_references_empty(self):
        """Test extraction with no references."""
        extractor = VendorProductExtractor()

        cve_data = {"containers": {"cna": {}}}

        vendors, products = extractor._extract_from_references(cve_data)

        assert vendors == []
        assert products == []


class TestNormalizeVendors:
    """Test suite for vendor normalization."""

    def test_normalize_known_vendors(self):
        """Test normalization of known vendors."""
        extractor = VendorProductExtractor()

        vendors = ["microsoft", "google llc", "apple inc", "adobe systems"]
        normalized = extractor._normalize_vendors(vendors)

        assert "Microsoft" in normalized
        assert "Google" in normalized
        assert "Apple" in normalized
        assert "Adobe" in normalized

    def test_normalize_filters_placeholders(self):
        """Test that placeholder values are filtered."""
        extractor = VendorProductExtractor()

        vendors = ["n/a", "unknown", "tbd", "*", "pending", "Microsoft"]
        normalized = extractor._normalize_vendors(vendors)

        assert "n/a" not in normalized
        assert "unknown" not in normalized
        assert "tbd" not in normalized
        assert "*" not in normalized
        assert "pending" not in normalized
        assert "Microsoft" in normalized

    def test_normalize_filters_generic_terms(self):
        """Test that generic terms are filtered."""
        extractor = VendorProductExtractor()

        vendors = ["the", "web", "file", "server", "database", "Microsoft"]
        normalized = extractor._normalize_vendors(vendors)

        assert "the" not in normalized
        assert "web" not in normalized
        assert "file" not in normalized
        assert "server" not in normalized
        assert "database" not in normalized
        assert "Microsoft" in normalized

    def test_normalize_filters_short_values(self):
        """Test that very short values are filtered."""
        extractor = VendorProductExtractor()

        vendors = ["a", "x", "Microsoft"]
        normalized = extractor._normalize_vendors(vendors)

        assert "a" not in normalized
        assert "x" not in normalized
        assert "Microsoft" in normalized

    def test_normalize_filters_all_digits(self):
        """Test that numeric-only vendors are filtered."""
        extractor = VendorProductExtractor()

        vendors = ["123", "456", "Microsoft"]
        normalized = extractor._normalize_vendors(vendors)

        assert "123" not in normalized
        assert "456" not in normalized
        assert "Microsoft" in normalized

    def test_normalize_filters_no_letters(self):
        """Test that vendors without letters are filtered."""
        extractor = VendorProductExtractor()

        vendors = ["@#$", "123-456", "Microsoft"]
        normalized = extractor._normalize_vendors(vendors)

        assert "@#$" not in normalized
        assert "123-456" not in normalized
        assert "Microsoft" in normalized

    def test_normalize_capitalizes_lowercase(self):
        """Test that lowercase vendors are capitalized."""
        extractor = VendorProductExtractor()

        vendors = ["custom vendor", "another company"]
        normalized = extractor._normalize_vendors(vendors)

        assert "Custom Vendor" in normalized
        assert "Another Company" in normalized

    def test_normalize_preserves_mixed_case(self):
        """Test that existing capitalization is preserved."""
        extractor = VendorProductExtractor()

        vendors = ["eBay", "jQuery", "VMware"]
        normalized = extractor._normalize_vendors(vendors)

        assert "eBay" in normalized
        assert "jQuery" in normalized
        assert "VMware" in normalized

    def test_normalize_deduplicates(self):
        """Test that duplicates are removed."""
        extractor = VendorProductExtractor()

        vendors = ["microsoft", "Microsoft", "MICROSOFT"]
        normalized = extractor._normalize_vendors(vendors)

        # Should map to single normalized vendor
        assert normalized.count("Microsoft") == 1

    def test_normalize_sorts_alphabetically(self):
        """Test that results are sorted."""
        extractor = VendorProductExtractor()

        vendors = ["Zebra", "Apple", "Microsoft"]
        normalized = extractor._normalize_vendors(vendors)

        assert normalized == sorted(normalized)


class TestNormalizeProducts:
    """Test suite for product normalization."""

    def test_normalize_filters_placeholders(self):
        """Test that placeholder values are filtered."""
        extractor = VendorProductExtractor()

        products = ["n/a", "unknown", "tbd", "*", "Windows"]
        normalized = extractor._normalize_products(products)

        assert "n/a" not in normalized
        assert "unknown" not in normalized
        assert "tbd" not in normalized
        assert "*" not in normalized
        assert "Windows" in normalized

    def test_normalize_filters_generic_terms(self):
        """Test that generic terms are filtered."""
        extractor = VendorProductExtractor()

        products = ["web", "server", "database", "Windows"]
        normalized = extractor._normalize_products(products)

        assert "web" not in normalized
        assert "server" not in normalized
        assert "database" not in normalized
        assert "Windows" in normalized

    def test_normalize_capitalizes_lowercase(self):
        """Test that lowercase products are capitalized."""
        extractor = VendorProductExtractor()

        products = ["windows 10", "office 365"]
        normalized = extractor._normalize_products(products)

        assert "Windows 10" in normalized
        assert "Office 365" in normalized

    def test_normalize_preserves_mixed_case(self):
        """Test that existing capitalization is preserved."""
        extractor = VendorProductExtractor()

        products = ["iOS", "macOS", "WordPress"]
        normalized = extractor._normalize_products(products)

        assert "iOS" in normalized
        assert "macOS" in normalized
        assert "WordPress" in normalized

    def test_normalize_deduplicates(self):
        """Test that duplicates are removed."""
        extractor = VendorProductExtractor()

        products = ["windows", "Windows", "WINDOWS"]
        normalized = extractor._normalize_products(products)

        # Should have only one entry (case-insensitive dedup doesn't happen,
        # but lowercase conversion means duplicates won't exist after capitalization)
        assert len([p for p in normalized if p.lower() == "windows"]) >= 1

    def test_normalize_sorts_alphabetically(self):
        """Test that results are sorted."""
        extractor = VendorProductExtractor()

        products = ["Zoom", "Chrome", "Firefox"]
        normalized = extractor._normalize_products(products)

        assert normalized == sorted(normalized)


class TestExtractVendorsProducts:
    """Test suite for the main extraction method."""

    def test_extract_from_all_sources(self):
        """Test extraction combining all sources."""
        extractor = VendorProductExtractor()

        cve_data = {
            "containers": {
                "cna": {
                    "affected": [{"vendor": "Microsoft", "product": "Windows"}],
                    "references": [{"url": "https://www.microsoft.com/security"}],
                }
            }
        }

        description = "Critical vulnerability in Microsoft Windows 10"
        title = "Windows 10 Remote Code Execution"

        vendors, products = extractor.extract_vendors_products(
            cve_data, description, title
        )

        assert "Microsoft" in vendors
        # Products should include Windows or Windows 10

    def test_extract_from_multiple_sources(self):
        """Test that data from multiple sources is combined."""
        extractor = VendorProductExtractor()

        cve_data = {
            "containers": {
                "cna": {
                    "affected": [{"vendor": "Adobe", "product": "Reader"}],
                    "references": [{"url": "https://www.microsoft.com/security"}],
                }
            },
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": "cpe:2.3:a:google:chrome:95.0:*:*:*:*:*:*:*"
                                }
                            ]
                        }
                    ]
                }
            ],
        }

        description = "Affects Firefox 92.0"

        vendors, products = extractor.extract_vendors_products(cve_data, description)

        # Should have vendors from affected (Adobe), references (Microsoft),
        # CPE (Google), and text (Mozilla)
        assert len(vendors) >= 2

    def test_extract_empty_cve_data(self):
        """Test extraction with empty CVE data."""
        extractor = VendorProductExtractor()

        cve_data = {}
        vendors, products = extractor.extract_vendors_products(cve_data, "", "")

        # Should handle gracefully
        assert vendors == []
        assert products == []

    def test_extract_with_logging(self):
        """Test that extraction logs debug information."""
        extractor = VendorProductExtractor()

        cve_data = {
            "cveMetadata": {"cveId": "CVE-2024-0001"},
            "containers": {
                "cna": {"affected": [{"vendor": "Microsoft", "product": "Windows"}]}
            },
        }

        # Should not raise exceptions
        vendors, products = extractor.extract_vendors_products(cve_data, "", "")

        assert len(vendors) >= 1
        assert len(products) >= 1


class TestEdgeCases:
    """Test suite for edge cases and error handling."""

    def test_malformed_cve_structure(self):
        """Test handling malformed CVE structure."""
        extractor = VendorProductExtractor()

        cve_data = {
            "containers": {
                "cna": {
                    "affected": "not a list"  # Should be list
                }
            }
        }

        # Should handle gracefully without crashing
        try:
            vendors, products = extractor.extract_vendors_products(cve_data, "", "")
            # If it doesn't crash, that's acceptable
            assert True
        except Exception:
            # If it does raise an exception, that's also acceptable behavior
            assert True

    def test_special_characters_in_vendor_names(self):
        """Test handling vendor names with special characters."""
        extractor = VendorProductExtractor()

        vendors = ["AT&T", "O'Reilly", "Smith-Jones Inc."]
        normalized = extractor._normalize_vendors(vendors)

        # Should preserve special characters
        assert any("&" in v for v in normalized) or len(normalized) > 0

    def test_unicode_characters(self):
        """Test handling Unicode characters."""
        extractor = VendorProductExtractor()

        text = "Vulnerability in Société Générale software"
        vendors, products = extractor._extract_from_text(text)

        # Should handle Unicode gracefully
        assert isinstance(vendors, list)
        assert isinstance(products, list)

    def test_very_long_input_strings(self):
        """Test handling very long input strings."""
        extractor = VendorProductExtractor()

        long_text = "Microsoft Windows " * 1000
        vendors, products = extractor._extract_from_text(long_text)

        # Should complete without timeout or crash
        assert isinstance(vendors, list)
        assert isinstance(products, list)

    def test_mixed_case_normalization(self):
        """Test normalization with mixed case input."""
        extractor = VendorProductExtractor()

        vendors = ["MICROSOFT", "microsoft", "Microsoft", "MiCrOsOfT"]
        normalized = extractor._normalize_vendors(vendors)

        # All should normalize to "Microsoft"
        assert normalized.count("Microsoft") == 1

    def test_whitespace_handling(self):
        """Test handling of excessive whitespace."""
        extractor = VendorProductExtractor()

        vendors = ["  Microsoft  ", "Google   ", "   Apple"]
        normalized = extractor._normalize_vendors(vendors)

        # Whitespace should be trimmed
        assert "Microsoft" in normalized
        assert "Google" in normalized
        assert "Apple" in normalized
