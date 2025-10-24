# CI/CD Performance Optimization Plan

**Status**: Planning Phase
**Created**: 2025-10-24
**Priority**: Medium (improves developer experience, not blocking)

## Current Performance Issues

### Test Execution Time
- **Problem**: Full test suite (743 tests) taking 15-20+ minutes in CI
- **Impact**: Slow feedback loop for developers, delayed deployments
- **Root Cause**: Sequential test execution, no caching, dependency reinstalls

### Dependency Installation
- **Problem**: Installing all dependencies on every run (~60s)
- **Impact**: Wasted time, especially for unchanged dependencies
- **Current**: No caching implemented

### Excluded Test Files
1. **test_static_page_agent.py** - Great Expectations/pyOpenSSL dependency conflict
   - **Error**: `AttributeError: module 'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'`
   - **Status**: Temporarily excluded with `--ignore` flag
   - **TODO**: Fix pyOpenSSL/cryptography version mismatch

2. **test_agent_base.py** - Tests written for old BaseAgent API
   - **Error**: `TypeError: Can't instantiate abstract class TestAgent without an implementation for abstract methods 'execute', 'get_dependencies'`
   - **Root Cause**: Tests expect methods that don't exist in current BaseAgent (agent_id, status(), log_info(), _cache_set(), _track_metric())
   - **Status**: Temporarily excluded with `--ignore` flag
   - **TODO**: Rewrite tests to match current BaseAgent implementation (get_status(), logger, etc.)

## Optimization Strategies

### 1. Test Parallelization with pytest-xdist

**Implementation**:
```yaml
- name: Run tests with coverage
  run: |
    pytest --cov=scripts \
           --cov-report=xml \
           --cov-report=json \
           --cov-report=term \
           --ignore=tests/test_static_page_agent.py \
           -n auto \  # Use all available CPUs
           --dist loadscope  # Distribute by test scope
```

**Expected Impact**: 50-70% reduction in test execution time
**Risk**: Low (pytest-xdist is well-tested)
**Effort**: 5 minutes (already in dependencies)

### 2. Dependency Caching

**Implementation** (uv pip cache):
```yaml
- name: Cache uv dependencies
  uses: actions/cache@v4
  with:
    path: ~/.cache/uv
    key: ${{ runner.os }}-uv-${{ hashFiles('requirements.txt') }}
    restore-keys: |
      ${{ runner.os }}-uv-

- name: Install dependencies
  run: |
    uv pip install --system -r requirements.txt
```

**Expected Impact**: 30-50s saved on dependency installation
**Risk**: Very Low
**Effort**: 10 minutes

### 3. Playwright Browser Caching

**Implementation**:
```yaml
- name: Cache Playwright browsers
  uses: actions/cache@v4
  with:
    path: ~/.cache/ms-playwright
    key: ${{ runner.os }}-playwright-${{ hashFiles('requirements.txt') }}
    restore-keys: |
      ${{ runner.os }}-playwright-

- name: Install Playwright browsers
  run: |
    playwright install --with-deps chromium
```

**Expected Impact**: 20-30s saved on browser installation
**Risk**: Low
**Effort**: 5 minutes

### 4. Test Splitting by Category

**Implementation**: Split tests into fast/slow groups
```yaml
jobs:
  test-fast:
    runs-on: ubuntu-latest
    steps:
      - name: Run fast tests (unit tests only)
        run: pytest tests/ -m "not slow" -n auto

  test-slow:
    runs-on: ubuntu-latest
    steps:
      - name: Run slow tests (integration/e2e)
        run: pytest tests/ -m "slow"
```

**Expected Impact**: Parallel execution of different test categories
**Risk**: Medium (requires test marking)
**Effort**: 30 minutes

### 5. Conditional Job Execution

**Implementation**: Skip jobs when not needed
```yaml
- name: Run tests with coverage
  if: |
    (github.event_name == 'push' && contains(github.event.head_commit.modified, 'scripts/')) ||
    (github.event_name == 'push' && contains(github.event.head_commit.modified, 'tests/')) ||
    github.event_name == 'pull_request'
  run: pytest --cov=scripts
```

**Expected Impact**: Skip unnecessary test runs for docs-only changes
**Risk**: Low
**Effort**: 15 minutes

### 6. Coverage-Only on Main Branch

**Implementation**: Run full coverage only on main pushes
```yaml
- name: Run tests (PR - no coverage)
  if: github.event_name == 'pull_request'
  run: pytest tests/ -n auto --ignore=tests/test_static_page_agent.py

- name: Run tests with coverage (main only)
  if: github.event_name == 'push' && github.ref == 'refs/heads/main'
  run: pytest --cov=scripts --cov-report=xml -n auto --ignore=tests/test_static_page_agent.py
```

**Expected Impact**: 10-15% faster PR runs
**Risk**: Very Low
**Effort**: 10 minutes

## Implementation Priority

### Phase 1: Quick Wins (Effort: 20 minutes, Impact: 60% faster)
1. ✅ Exclude problematic test file (Done: commit f369edc56)
2. Enable pytest-xdist parallelization
3. Add uv pip dependency caching

### Phase 2: Medium Improvements (Effort: 45 minutes, Impact: 20% faster)
4. Add Playwright browser caching
5. Implement conditional job execution
6. Coverage-only on main branch

### Phase 3: Advanced Optimizations (Effort: 2 hours, Impact: 15% faster)
7. Test splitting by category
8. Matrix testing for different Python versions
9. Fail-fast strategy for quick feedback

## Expected Total Impact

**Current CI Time**: ~20 minutes
**Phase 1 Optimizations**: ~8 minutes (60% reduction)
**Phase 2 Optimizations**: ~6 minutes (25% additional reduction)
**Phase 3 Optimizations**: ~5 minutes (17% additional reduction)

**Target CI Time**: < 5 minutes for standard PRs

## Known Issues to Fix

### 1. Great Expectations Dependency Conflict
**Issue**: `AttributeError: module 'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'`
**Root Cause**: pyOpenSSL/cryptography version mismatch in Great Expectations
**Temporary Fix**: Exclude test_static_page_agent.py
**Permanent Fix**: Upgrade pyOpenSSL and cryptography, or remove Great Expectations

**Implementation**:
```bash
# Option 1: Update dependencies
pip install --upgrade pyOpenSSL cryptography

# Option 2: Pin compatible versions in requirements.txt
pyOpenSSL>=24.0.0
cryptography>=42.0.0

# Option 3: Remove Great Expectations (if unused)
grep -r "great_expectations" scripts/ tests/
# If only used in static_page_agent, consider removing
```

## Monitoring & Validation

### Metrics to Track
1. **Test Duration**: Total time from start to test completion
2. **Coverage Upload Time**: Time to upload coverage reports
3. **Cache Hit Rate**: Percentage of successful cache restores
4. **Failure Rate**: Number of flaky tests or timeouts

### Success Criteria
- CI runtime < 8 minutes for PR builds
- CI runtime < 10 minutes for main branch builds
- 95%+ cache hit rate on unchanged dependencies
- Zero test collection errors

## References
- [pytest-xdist Documentation](https://pytest-xdist.readthedocs.io/)
- [GitHub Actions Caching](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows)
- [pytest Performance Tips](https://docs.pytest.org/en/stable/example/simple.html#incremental-testing-test-steps)
