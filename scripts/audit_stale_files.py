#!/usr/bin/env python3
"""
Comprehensive stale files audit script to identify all CVE files that shouldn't exist.
"""

import json
import os
from pathlib import Path
from datetime import datetime, timezone
import click

@click.command()
@click.option('--output-dir', type=Path, default=Path('public'), help='Output directory to audit')
@click.option('--api-dir', type=Path, default=Path('api'), help='API directory with valid data')
@click.option('--min-epss', type=float, default=0.6, help='Minimum EPSS threshold')
def audit_stale_files(output_dir: Path, api_dir: Path, min_epss: float):
    """Audit for stale CVE files in the output directory."""
    
    print(f"🔍 Auditing stale files in {output_dir}")
    print(f"   Minimum EPSS threshold: {min_epss*100}%")
    
    # Get valid CVE IDs from API data
    valid_cve_ids = set()
    api_index = api_dir / "vulns" / "index.json"
    
    if api_index.exists():
        with open(api_index) as f:
            data = json.load(f)
            for vuln in data.get("vulnerabilities", []):
                epss_score = vuln.get("epss", {}).get("score", 0)
                if epss_score >= min_epss:
                    valid_cve_ids.add(vuln["cveId"])
    
    print(f"✅ Found {len(valid_cve_ids)} valid CVEs with EPSS ≥ {min_epss*100}%")
    
    # Scan output directory for CVE files
    stale_files = []
    all_cve_files = []
    
    # Check for CVE HTML pages
    if output_dir.exists():
        # Pattern 1: cves/CVE-*/index.html
        for cve_dir in output_dir.glob("cves/CVE-*"):
            if cve_dir.is_dir():
                cve_id = cve_dir.name
                all_cve_files.append(str(cve_dir))
                if cve_id not in valid_cve_ids:
                    stale_files.append({
                        "path": str(cve_dir),
                        "cve_id": cve_id,
                        "type": "html_directory"
                    })
        
        # Pattern 2: api/cves/CVE-*.json
        for json_file in output_dir.glob("api/cves/CVE-*.json"):
            cve_id = json_file.stem
            all_cve_files.append(str(json_file))
            if cve_id not in valid_cve_ids:
                stale_files.append({
                    "path": str(json_file),
                    "cve_id": cve_id,
                    "type": "api_json"
                })
        
        # Pattern 3: Direct CVE pages
        for html_file in output_dir.glob("CVE-*.html"):
            cve_id = html_file.stem
            all_cve_files.append(str(html_file))
            if cve_id not in valid_cve_ids:
                stale_files.append({
                    "path": str(html_file),
                    "cve_id": cve_id,
                    "type": "html_page"
                })
    
    # Check API directory separately if different from output
    if api_dir != output_dir and api_dir.exists():
        for json_file in (api_dir / "vulns").glob("vulns-*.json"):
            with open(json_file) as f:
                chunk_data = json.load(f)
                chunk_stale = 0
                for vuln in chunk_data.get("vulnerabilities", []):
                    epss_score = vuln.get("epss", {}).get("score", 0)
                    if epss_score < min_epss:
                        chunk_stale += 1
                
                if chunk_stale > 0:
                    stale_files.append({
                        "path": str(json_file),
                        "cve_id": f"{chunk_stale} stale CVEs in chunk",
                        "type": "chunk_file"
                    })
    
    # Generate report
    stale_cve_ids = [f["cve_id"] for f in stale_files if "CVE-" in f["cve_id"]]
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "audit_summary": {
            "total_cve_files_found": len(all_cve_files),
            "valid_cves": len(valid_cve_ids),
            "stale_files": len(stale_files),
            "directories_scanned": [str(output_dir), str(api_dir)]
        },
        "stale_files": stale_files[:100],  # Limit to first 100 for readability
        "sample_stale_cve_ids": list(set(stale_cve_ids[:20]))
    }
    
    # Save JSON report
    report_path = Path("stale_files_report.json")
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Generate markdown summary
    summary = f"""# Stale Files Audit Report

**Generated**: {report['timestamp']}

## Summary
- **Total CVE files found**: {report['audit_summary']['total_cve_files_found']}
- **Valid CVEs (EPSS ≥ {min_epss*100}%)**: {report['audit_summary']['valid_cves']}
- **Stale files detected**: {report['audit_summary']['stale_files']}

## Stale File Types
"""
    
    type_counts = {}
    for file in stale_files:
        file_type = file['type']
        type_counts[file_type] = type_counts.get(file_type, 0) + 1
    
    for file_type, count in type_counts.items():
        summary += f"- **{file_type}**: {count} files\n"
    
    if stale_files:
        summary += f"\n## Sample Stale CVE IDs\n"
        for cve_id in report['sample_stale_cve_ids']:
            summary += f"- {cve_id}\n"
        
        summary += f"\n## Action Required\n"
        summary += f"Run `npm run clean` or `python -m scripts.cleanup_stale_files --force-purge` to remove these files.\n"
    else:
        summary += f"\n✅ No stale files detected!\n"
    
    # Save markdown summary
    summary_path = Path("stale_files_summary.md")
    with open(summary_path, 'w') as f:
        f.write(summary)
    
    # Print results
    print(f"\n📊 Audit Results:")
    print(f"   Total CVE files: {len(all_cve_files)}")
    print(f"   Stale files: {len(stale_files)}")
    print(f"   Reports saved: {report_path}, {summary_path}")
    
    if stale_files:
        print(f"\n❌ Found {len(stale_files)} stale files!")
        print(f"   Sample stale CVEs: {', '.join(report['sample_stale_cve_ids'][:5])}")
    else:
        print(f"\n✅ No stale files found!")

if __name__ == "__main__":
    audit_stale_files()