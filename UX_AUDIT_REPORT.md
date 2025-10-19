# UX Audit Report - Vulnerability Intelligence Dashboard

**Date:** 2025-10-19
**Auditor:** UX Expert Agent
**Scope:** Dashboard UI/UX, Filters, Navigation, Data Presentation

---

## Executive Summary

This audit identifies critical UX issues in the Vulnerability Intelligence Dashboard, particularly focusing on **vestigial features** that no longer serve their purpose due to the EPSS 60% threshold enforcement. The dashboard has 30 vulnerabilities (all EPSS ≥60%), but the UI still contains filters and features designed for a broader dataset.

**Critical Finding:** Since ALL data now meets the EPSS ≥60% threshold, the EPSS filter (0-100%) and its related UI components are **functionally useless** and create confusion.

---

## 🔴 Critical Issues (Immediate Action Required)

### 1. **Broken CVE Detail Links**
**Severity:** CRITICAL
**Location:** `/public/index.html` line 703

**Problem:**
```html
<a :href="`/vuln-bot/cves/${vuln.cve_id}/`" class="cve-link" x-text="vuln.cve_id"></a>
```

The CVE links point to `/vuln-bot/cves/CVE-XXXX/` but:
- No individual CVE pages exist at this path
- API data shows chunked storage: `vulns-2025-CRITICAL.json`, etc.
- Clicking any CVE ID results in a **404 error**

**Impact:** Users cannot access detailed vulnerability information, rendering the primary interaction pattern broken.

**Recommended Fix:**
1. Implement modal-based CVE details using `CveModal.ts` (already exists but not integrated)
2. OR generate individual CVE detail pages during build
3. OR redirect to NVD/CVE.org with external link indicator

---

### 2. **Vestigial EPSS Filter (60-100%)**
**Severity:** CRITICAL (Confusion/Misleading)
**Location:** `/public/index.html` lines 618-623, dashboard.ts lines 146-147

**Problem:**
```html
<div class="filter-group">
    <label>EPSS %</label>
    <div style="display: flex; gap: 0.5rem;">
        <input type="number" x-model.number="filters.epss_min" placeholder="Min" min="0" max="100" value="70">
        <input type="number" x-model.number="filters.epss_max" placeholder="Max" min="0" max="100" value="100">
    </div>
</div>
```

**Why This Is Broken:**
- ALL 30 vulnerabilities have EPSS ≥98% (range: 98.22% - 99.84%)
- The filter allows values 0-60%, which would filter out **ALL data**
- Users adjusting this filter will only see empty results
- The "70%" placeholder is misleading (should be 60% minimum)
- This filter serves NO purpose given the data curation strategy

**Evidence from Data:**
```json
// All CVEs have epss_percentile ≥98%
"epss_percentile": 99.628  // Lowest: 98.221
"epss_percentile": 99.807  // Highest: 99.84
```

**Recommended Fix:**
- **Option A (Recommended):** Remove EPSS filter entirely + add info badge: "All vulnerabilities meet EPSS ≥60% threshold"
- **Option B:** Convert to read-only display showing the threshold enforcement
- **Option C:** Add warning when EPSS min <60%: "No results - all data meets ≥60% threshold"

---

### 3. **Misleading EPSS Chart (90-100% Only)**
**Severity:** HIGH
**Location:** `/public/index.html` lines 657-662, 1983-2014

**Problem:**
```javascript
labels: ['90-100%', '70-89%', '50-69%', '<50%'],
datasets: [{
    data: [
        this.stats.epss_distribution['90-100%'],  // = 30
        this.stats.epss_distribution['70-89%'],   // = 0
        this.stats.epss_distribution['50-69%'],   // = 0
        this.stats.epss_distribution['<50%']      // = 0
    ],
```

**Why This Is Broken:**
- Chart shows 4 buckets but only 1 has data (90-100% = 30)
- Creates a visually misleading "all or nothing" bar chart
- Wastes screen real estate on empty categories
- Doesn't reflect the actual data distribution (98-100%)

**Recommended Fix:**
- Replace with granular breakdown: "98-98.5%", "98.5-99%", "99-99.5%", "99.5-100%"
- OR show "Top 1% EPSS" badge instead of chart
- OR remove chart and replace with metric: "Average EPSS: 99.2%"

---

### 4. **"Today's CVEs" Quick Filter (Always Empty)**
**Severity:** HIGH
**Location:** `/public/index.html` lines 560-564, 1786-1789

**Problem:**
```javascript
else if (this.quickFilter === 'today') {
    const today = new Date().toISOString().split('T')[0];
    vulns = vulns.filter(v => v.published_date && v.published_date.startsWith(today));
}
```

**Why This Is Broken:**
- Data shows: `"generated": "2025-08-02T05:14:56"` (77 days ago)
- Most recent CVE: `"published_short": "2025-07-10"`
- Clicking "Today's CVEs" will **always return 0 results**
- No indication that data is stale

**Evidence:**
```json
{
  "generated": "2025-08-02T05:14:56.702832",
  "count": 30,
  // Latest CVE is from July 10, 2025
  "published_date": "2025-07-10T00:00:00+00:00"
}
```

**Recommended Fix:**
- Replace with "Last 7 Days" or "Last 30 Days"
- OR add data freshness indicator: "Last updated: Aug 2, 2025"
- OR remove quick filter if data is not updated daily

---

### 5. **"KEV Listed" Quick Filter (Always Empty)**
**Severity:** HIGH
**Location:** `/public/index.html` lines 565-569, 1789-1791

**Problem:**
```javascript
else if (this.quickFilter === 'kev') {
    vulns = vulns.filter(v => v.tags.includes('KEV'));
}
```

**Why This Is Broken:**
- Stats show: `"kev_count": 0`
- Filter checks `tags` array for "KEV" but data shows:
  ```json
  "kev_status": false,  // Field exists but not used
  "tags": ["CWE-158"]   // Only CWE tags
  ```
- The filter logic is checking the wrong field
- Badge shows "⭐ KEV Listed" but will always return 0 results

**Recommended Fix:**
- **Option A:** Fix filter to check `kev_status` boolean
- **Option B:** Remove KEV quick filter if no KEV vulnerabilities exist
- **Option C:** Add badge showing KEV count (currently shows as "0")

---

## ⚠️ Vestigial Content (Cleanup Recommended)

### 6. **Severity Filter (Minimal Value)**
**Severity:** MEDIUM
**Location:** `/public/index.html` lines 600-607

**Problem:**
- Distribution: 23 CRITICAL, 7 HIGH, 0 MEDIUM, 0 LOW
- MEDIUM and LOW options are dead ends
- 77% of data is CRITICAL already

**Recommended Fix:**
- Keep filter but add counts: "Critical (23)", "High (7)", "Medium (0)", "Low (0)"
- OR simplify to toggle: "Critical Only" vs "All"

---

### 7. **Network Attack Vector Filter (Always True)**
**Severity:** MEDIUM
**Location:** `/public/index.html` lines 571-574

**Problem:**
```javascript
else if (this.quickFilter === 'network') {
    vulns = vulns.filter(v => v.attack_vector === 'NETWORK');
}
```

**Why This Is Vestigial:**
- All 30 CVEs show: `"attack_vector": "Network"`
- Filter will always return all results
- Provides no filtering value

**Evidence:** Every CVE in the dataset:
```json
"attack_vector": "Network"
```

**Recommended Fix:**
- Remove "Network Vector" quick filter
- OR replace with "Remote Exploitable" (more meaningful)

---

### 8. **Week Count Stats (Shows "0")**
**Severity:** LOW
**Location:** `/public/index.html` lines 515-517

**Problem:**
```html
<div class="stat-change positive">
    <span x-text="`+${stats.week_count}`"></span>  <!-- Shows "+0" -->
    <span>from last week</span>
</div>
```

**Why This Is Confusing:**
- Shows "+0 from last week" (data is 77 days old)
- Creates false impression of real-time updates
- Stats show: `"week_count": 0, "today_count": 0`

**Recommended Fix:**
- Replace with: "Last updated: Aug 2, 2025"
- OR remove if not updated frequently

---

## 🔍 Improvement Opportunities

### 9. **Missing CVSS Filter Logic**
**Severity:** MEDIUM
**Location:** dashboard.ts lines 1810-1824

**Problem:**
- CVSS filter exists in UI but defaults to `null` (inactive)
- Range is 7.5-10.0 but filter allows 0-10
- Most users won't adjust this filter due to unclear value

**Recommended Enhancement:**
- Pre-set CVSS ≥7.0 (High+ severity)
- Add slider UI instead of text inputs
- Show distribution: "7-8 (X), 8-9 (Y), 9-10 (Z)"

---

### 10. **Poor Mobile Table Experience**
**Severity:** MEDIUM
**Location:** `/public/index.html` lines 415-420, 673-717

**Problem:**
```css
@media (max-width: 768px) {
    /* Hide less important columns on mobile */
    th:nth-child(5), td:nth-child(5) { /* Risk Score */
        display: none;
    }
```

**Issues:**
- Table requires horizontal scroll on mobile
- Risk Score hidden but EPSS% shown (both are percentile-based)
- Scroll indicator only shows on hover (useless on touch devices)

**Recommended Fix:**
- Implement card-based layout for mobile (<768px)
- Show: CVE ID, Severity, CVSS, Published Date (essentials only)
- "Expand" button for full details

---

### 11. **Confusing EPSS Percentile Display**
**Severity:** LOW
**Location:** Multiple (table header, chart, export)

**Problem:**
- Shows "EPSS %" but actually displays **percentile** (99.6), not score (0.996)
- Creates confusion: "99.6%" exploitation probability vs "top 99.6 percentile"

**Evidence:**
```json
"epssScore": 90.99,        // Actual EPSS score
"epssPercentile": 99.628,  // Percentile ranking
```

Dashboard shows: `<td x-text="vuln.epss_percentile"></td>` labeled as "EPSS %"

**Recommended Fix:**
- Label as "EPSS Percentile" or "EPSS Rank"
- Add tooltip: "Percentile rank among all CVEs (higher = more likely to be exploited)"
- OR show actual EPSS score (0-100%) for clarity

---

### 12. **No Exploit Status Indicators**
**Severity:** MEDIUM
**Location:** Data exists but not displayed

**Problem:**
- Data includes: `"exploitation_status": "Unknown"`, `"kev_status": false`
- Not shown in table or detail view
- Users cannot identify actively exploited CVEs

**Recommended Enhancement:**
- Add "Exploitation Status" column with badges:
  - 🔴 "Active Exploitation" (if KEV)
  - 🟡 "Exploit Available"
  - ⚪ "Unknown"

---

## 🎯 Recommended Actions (Prioritized)

### Immediate (Week 1)
1. **Fix broken CVE links** - Implement modal or generate pages
2. **Remove/Redesign EPSS filter** - Add threshold badge instead
3. **Fix KEV filter logic** - Check `kev_status` not `tags`
4. **Remove "Today's CVEs" filter** - Replace with "Last 7 Days"

### Short-term (Week 2-3)
5. **Redesign EPSS chart** - Show granular distribution or remove
6. **Remove Network Vector filter** - All are network-based
7. **Add data freshness indicator** - Show last update timestamp
8. **Add Exploitation Status column** - Surface KEV/exploit data

### Medium-term (Month 1-2)
9. **Mobile card layout** - Replace horizontal scroll table
10. **Add CVSS slider filter** - Better than text inputs
11. **Clarify EPSS labeling** - Percentile vs Score
12. **Add severity counts to filter** - Show "(23)" next to Critical

### Nice-to-Have (Backlog)
- Implement saved filters/searches (component exists but not integrated)
- Add vulnerability trend timeline
- Export filtered results (CSV exists but no date range)
- Dark/light theme toggle

---

## 📊 Impact Analysis

### High Impact (User Cannot Complete Task)
- **Broken CVE Links:** Users cannot view vulnerability details
- **EPSS Filter Confusion:** Users get empty results and don't know why

### Medium Impact (User Frustrated But Can Work Around)
- **Dead-end Filters:** KEV, Today's CVEs return no results
- **Misleading Stats:** "0 this week" creates false impression

### Low Impact (Minor Annoyance)
- **Vestigial Filters:** Network Vector always returns all results
- **EPSS Labeling:** Confusing but functional

---

## 🔧 Technical Debt

### Components Not Integrated
- `CveModal.ts` - Fully implemented but not connected to dashboard
- `SavedSearches.ts` - Component exists but no UI integration
- `DataVisualization.ts` - Referenced but not in use

### Data Model Inconsistencies
- Dashboard uses `snake_case`: `epss_percentile`, `cvss_score`
- TypeScript types use `camelCase`: `epssPercentile`, `cvssScore`
- Transformation happens at runtime (line 344-369) - creates overhead

---

## 📝 Accessibility Issues

### Keyboard Navigation
✅ **Good:** Shortcuts documented (/, r, e)
⚠️ **Issue:** No visible keyboard shortcut indicator
⚠️ **Issue:** Modal keyboard traps implemented but modal not integrated

### Screen Reader Support
✅ **Good:** Filter announcements implemented
❌ **Critical:** CVE links go to 404 pages (confusing for SR users)
⚠️ **Issue:** EPSS chart has no `aria-label` description

### Color Contrast
✅ **Good:** Severity badges have good contrast
⚠️ **Issue:** Muted text (`--text-muted: #6b6b85`) may fail WCAG AA on dark backgrounds

---

## 🎨 Design Inconsistencies

1. **Quick Filters vs Advanced Filters:**
   - Quick filters use `filter-chip` class
   - Advanced filters use `filter-group` class
   - Both modify same underlying state (confusing)

2. **Empty State Handling:**
   - No message when filters return 0 results
   - Just shows empty table (user doesn't know if it's an error)

3. **Loading States:**
   - Dashboard.ts has `loading` state but not visualized
   - No skeleton loaders or spinners

---

## 📈 Metrics to Track Post-Fix

1. **Click-through rate on CVE links** (currently 0% due to 404s)
2. **Filter usage rates** (expect EPSS filter to drop to 0% after fix)
3. **Mobile bounce rate** (should decrease with card layout)
4. **Export usage** (add tracking to CSV export)
5. **Keyboard shortcut usage** (track / r e keys)

---

## Conclusion

The dashboard suffers from **vestigial features** carried over from a broader vulnerability dataset. Now that ALL data meets EPSS ≥60%, many filters are **functionally useless or broken**:

- ❌ EPSS filter (0-100% range is misleading)
- ❌ EPSS chart (empty buckets waste space)
- ❌ "Today's CVEs" (data is 77 days old)
- ❌ "KEV Listed" (wrong field checked)
- ❌ "Network Vector" (all are network-based)
- ❌ CVE detail links (all 404)

**Priority:** Fix critical path (CVE links) and remove/redesign vestigial filters to match the curated dataset.

---

**End of Report**
