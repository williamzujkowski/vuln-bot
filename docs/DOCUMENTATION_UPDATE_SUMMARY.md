# Documentation Update Summary

## Latest Update: 2025-06-30

### Overview
Completed a comprehensive review and update of all documentation files to ensure accuracy and remove outdated content.

### Changes Made

#### Updated Files
1. **README.md**
   - Updated coverage badge from 54% to 77% to reflect current test coverage
   - Added testing requirements section with CI minimum (63%) and target (80%)
   - Updated running tests command to show coverage report format

2. **CONTRIBUTING.md**
   - Updated repository URL from wclaytor to williamzujkowski

3. **CHANGELOG.md**
   - Updated repository URL from wclaytor to williamzujkowski

4. **CLAUDE.md**
   - No changes needed - already up to date

5. **MANIFEST.yaml**
   - No changes needed - already accurate

#### Removed Files
Consolidated and removed all vestigial archive files from `docs/archive/`:
- `IMPLEMENTATION_PLAN.md` - Historical sprint planning, no longer relevant
- `IMPLEMENTATION_STATUS.md` - Outdated status tracking, replaced by current documentation
- `NEXT_STEPS.md` - Outdated next steps, current status reflected in main docs
- `KICKSTART_ANALYSIS.md` - Initial analysis document, no longer needed
- `project_plan.md` - Original project planning, superseded by current docs
- `test_report.md` - Old test report, current coverage in README
- `storage_comparison.md` - Storage strategy analysis, decision already implemented

### Key Information Preserved
- Test coverage requirements (63% CI minimum, 80% target) added to README
- Current test coverage (77%) reflected in badge and test commands
- All other useful information was already present in the main documentation

### Result
- Documentation is now accurate and up-to-date
- Removed 7 outdated archive files
- Consolidated useful information into existing documentation
- All repository URLs point to correct GitHub account

---

## Previous Update: 2025-06-29

### Overview
This section summarizes the documentation updates made to reflect the rebranding to Vuln-Bot and the implementation of chunked storage.

### Updated Files

#### Core Documentation
1. **README.md**
   - Rebranded to "Vuln-Bot"
   - Updated focus to EPSS ≥ 70% filtering
   - Added chunked storage information
   - Updated API documentation for chunked endpoints
   - Corrected performance metrics

2. **CLAUDE.md**
   - Updated branding and project description
   - Corrected EPSS threshold to 70%
   - Added chunked storage generation commands
   - Updated content generation section for chunks

3. **MANIFEST.yaml**
   - Simplified to avoid duplication with README
   - Updated branding and focus
   - Added chunked storage mention

4. **CONTRIBUTING.md**
   - Updated project name
   - Increased coverage requirement to 80%

5. **CHANGELOG.md**
   - Added unreleased section with rebranding changes
   - Documented chunked storage implementation

#### Other Documentation
- **docs/RELEASE.md** - Updated branding
- **docs/design-system.md** - Updated branding
- **tests/README.md** - Updated branding

### Key Changes
1. All references to "Morning Vuln Briefing" updated to "Vuln-Bot"
2. EPSS threshold corrected from 0.1% to 70% throughout
3. Added documentation for chunked storage (8 files vs 33,000+)
4. Removed redundant and outdated documentation
5. Preserved historical documents in archive folder