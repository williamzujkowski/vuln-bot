#!/usr/bin/env python3
"""
Test Coverage Improvement Script
Analyzes current test coverage and generates missing tests
"""

import json
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple


class TestCoverageAnalyzer:
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.scripts_dir = self.project_root / "scripts"
        self.tests_dir = self.project_root / "tests"

    def get_coverage_report(self) -> Dict:
        """Run coverage and get detailed report"""
        cmd = [
            "pytest",
            "--cov=scripts",
            "--cov-report=json",
            "--cov-report=term-missing",
            "-q",
            "tests/"
        ]

        subprocess.run(cmd, capture_output=True, text=True)

        # Load coverage.json
        coverage_file = self.project_root / "coverage.json"
        if coverage_file.exists():
            with open(coverage_file) as f:
                return json.load(f)
        return {}

    def find_uncovered_functions(self, coverage_data: Dict) -> Dict[str, List[Tuple[int, int]]]:
        """Find functions and lines that need coverage"""
        uncovered = {}

        files = coverage_data.get('files', {})
        for filepath, file_data in files.items():
            if not filepath.startswith('scripts/'):
                continue

            missing_lines = file_data.get('missing_lines', [])
            if missing_lines:
                uncovered[filepath] = []
                # Group consecutive lines
                if missing_lines:
                    start = missing_lines[0]
                    end = missing_lines[0]

                    for line in missing_lines[1:]:
                        if line == end + 1:
                            end = line
                        else:
                            uncovered[filepath].append((start, end))
                            start = end = line
                    uncovered[filepath].append((start, end))

        return uncovered

    def analyze_skipped_tests(self) -> List[str]:
        """Find all skipped tests"""
        skipped = []

        for test_file in self.tests_dir.rglob("test_*.py"):
            content = test_file.read_text()
            if "pytest.skip" in content or "@pytest.mark.skip" in content:
                # Count skipped tests
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if 'pytest.skip' in line or '@pytest.mark.skip' in line:
                        skipped.append(f"{test_file}:{i+1}")

        return skipped

    def generate_coverage_report(self):
        """Generate comprehensive coverage report"""
        print("🔍 Analyzing Test Coverage...")

        coverage_data = self.get_coverage_report()
        if not coverage_data:
            print("❌ Failed to generate coverage report")
            return

        totals = coverage_data.get('totals', {})
        current_coverage = totals.get('percent_covered', 0)

        print(f"\n📊 Current Coverage: {current_coverage:.1f}%")
        print("   Target Coverage: 90%")
        print(f"   Gap: {90 - current_coverage:.1f}%")

        # Find uncovered code
        uncovered = self.find_uncovered_functions(coverage_data)
        print("\n📝 Files needing coverage:")
        for filepath, ranges in sorted(uncovered.items()):
            module_cov = coverage_data['files'][filepath]['summary']['percent_covered']
            print(f"   {filepath}: {module_cov:.1f}% covered")
            for start, end in ranges[:3]:  # Show first 3 ranges
                if start == end:
                    print(f"      - Line {start}")
                else:
                    print(f"      - Lines {start}-{end}")

        # Find skipped tests
        skipped = self.analyze_skipped_tests()
        if skipped:
            print(f"\n⚠️  Found {len(skipped)} skipped tests:")
            for test in skipped[:5]:  # Show first 5
                print(f"   - {test}")

        # Recommendations
        print("\n💡 Recommendations:")
        print("   1. Remove or implement all skipped tests")
        print("   2. Focus on low-coverage modules first")
        print("   3. Add integration tests for agent workflows")
        print("   4. Test error handling paths")
        print("   5. Add edge case tests")

        return current_coverage, uncovered, skipped


def main():
    analyzer = TestCoverageAnalyzer()
    current_coverage, uncovered, skipped = analyzer.generate_coverage_report()

    # Generate action items
    print("\n🎯 Action Items:")
    print("   1. Fix skipped tests in test_normalizer_extended.py")
    print("   2. Enable E2E Playwright tests")
    print("   3. Add missing test coverage for:")

    # Find lowest coverage files
    coverage_file = Path("coverage.json")
    if coverage_file.exists():
        with open(coverage_file) as f:
            data = json.load(f)

        files = [(f, d['summary']['percent_covered'])
                 for f, d in data['files'].items()
                 if f.startswith('scripts/') and d['summary']['percent_covered'] < 80]

        for filepath, cov in sorted(files, key=lambda x: x[1])[:5]:
            print(f"      - {filepath}: {cov:.1f}%")


if __name__ == "__main__":
    main()
