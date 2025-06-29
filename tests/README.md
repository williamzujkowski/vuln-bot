# Frontend Tests

This directory contains comprehensive tests for Vuln-Bot frontend components.

## Test Structure

```
tests/
├── README.md           # This file
├── setup.ts           # Test setup and global mocks
├── test_frontend.html # Browser-based test suite (Mocha/Chai)
├── dashboard.test.ts  # Vulnerability Dashboard tests
└── analytics.test.ts  # Analytics module tests
```

## Running Tests

### Unit Tests (Vitest)

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run with coverage
npm run test:coverage

# Open test UI
npm run test:ui
```

### Browser Tests

Open `test_frontend.html` in a web browser to run the Mocha/Chai test suite.

## Test Coverage

The test suites cover:

### Dashboard Tests
- Data loading and API integration
- Filtering functionality (search, severity, scores, etc.)
- Sorting capabilities
- Pagination
- URL state management
- CSV export
- Statistics calculation
- Error handling

### Analytics Tests
- Privacy compliance (DNT header)
- Event tracking
- Performance monitoring
- User interaction tracking
- Session management
- Data persistence
- Auto-flush functionality

### Browser Tests
- DOM manipulation
- Accessibility (ARIA labels, keyboard navigation)
- Performance with large datasets
- Cross-browser compatibility

## Writing Tests

### Unit Tests

```typescript
import { describe, it, expect } from 'vitest';
import { MyModule } from '../src/assets/ts/myModule';

describe('MyModule', () => {
  it('should do something', () => {
    const result = MyModule.doSomething();
    expect(result).toBe(expected);
  });
});
```

### Mocking

Use Vitest's built-in mocking capabilities:

```typescript
import { vi } from 'vitest';

// Mock a module
vi.mock('../src/assets/ts/api', () => ({
  fetchData: vi.fn().mockResolvedValue(mockData),
}));

// Mock global objects
global.fetch = vi.fn();
```

## Test Utilities

The `setup.ts` file provides global test utilities:

- `createMockVulnerability()` - Creates a mock vulnerability object
- Mock implementations for browser APIs (matchMedia, IntersectionObserver, etc.)

## Best Practices

1. **Test Organization**: Group related tests using `describe` blocks
2. **Test Names**: Use descriptive test names that explain what is being tested
3. **Isolation**: Each test should be independent and not rely on other tests
4. **Mocking**: Mock external dependencies to ensure tests are deterministic
5. **Coverage**: Aim for high test coverage but focus on critical paths
6. **Performance**: Keep tests fast by minimizing I/O and using mocks

## Troubleshooting

### Common Issues

1. **TypeScript Errors**: Run `npm run type-check` to identify type issues
2. **Import Errors**: Check that path aliases are configured in `vitest.config.ts`
3. **DOM Not Available**: Ensure `environment: 'jsdom'` is set in Vitest config
4. **Async Tests**: Always use `async/await` or return promises in async tests

### Debug Mode

Run tests with additional logging:

```bash
# Run with debug output
DEBUG=* npm test
```