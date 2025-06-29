# Storage Strategy Comparison

## Current Problem
- Generating 33,027 individual JSON files
- Each file ~1-2KB = ~33MB total
- Git struggles with this many files
- Slow clone/pull operations
- GitHub UI may have issues

## Storage Strategies

### 1. Severity-Year Chunks
**Organization**: Group by severity level and year
```
vulns-2024-CRITICAL.json (50 vulns)
vulns-2024-HIGH.json (150 vulns)
vulns-2024-MEDIUM.json (300 vulns)
vulns-2025-CRITICAL.json (30 vulns)
etc.
```

**Pros**:
- Logical organization
- Easy to find vulns by severity/year
- ~7-9 files total
- Good for filtering

**Cons**:
- Uneven file sizes
- May need to load multiple files

### 2. Size-Based Chunks
**Organization**: Fixed number per file (e.g., 1000 vulns/file)
```
vulns-chunk-001.json (1000 vulns)
vulns-chunk-002.json (1000 vulns)
vulns-chunk-003.json (1000 vulns)
...
vulns-chunk-034.json (27 vulns)
```

**Pros**:
- Predictable file sizes
- Easy pagination
- ~34 files total

**Cons**:
- No logical grouping
- Need index to find specific vuln

### 3. Single File
**Organization**: Everything in one file
```
vulns-complete.json (33,027 vulns)
```

**Pros**:
- Simplest approach
- One file to manage
- Fast searching

**Cons**:
- Large file (~30MB)
- Slower initial load
- May hit browser limits

### 4. Hybrid (Year + Chunks)
**Organization**: Year folders with size chunks
```
2024/
  vulns-001.json (1000 vulns)
  vulns-002.json (500 vulns)
2025/
  vulns-001.json (200 vulns)
```

**Pros**:
- Organized by year
- Manageable file sizes
- Good for archiving

**Cons**:
- More complex
- Multiple directories

## Recommendation

**Severity-Year Chunks** is the best option because:
1. Reduces 33,027 files to ~7-9 files
2. Maintains logical organization
3. Aligns with how users filter (by severity)
4. Reasonable file sizes (1-5MB each)
5. Easy to implement
6. Good performance balance

The dashboard already filters by severity, so this organization maps naturally to user behavior.