# Release Process

This document describes how to create a new release of Vuln-Bot.

## Prerequisites

- Ensure all tests are passing: `npm test && pytest`
- Ensure the main branch is up to date
- Ensure you have push access to the repository

## Creating a Release

### Automatic Method (Recommended)

1. **Bump the version:**
   ```bash
   # For a patch release (e.g., 1.0.0 -> 1.0.1)
   python scripts/bump_version.py patch
   
   # For a minor release (e.g., 1.0.0 -> 1.1.0)
   python scripts/bump_version.py minor
   
   # For a major release (e.g., 1.0.0 -> 2.0.0)
   python scripts/bump_version.py major
   ```

2. **Push the changes and tag:**
   ```bash
   git push origin main
   git push origin v1.0.1  # Replace with your version
   ```

3. The GitHub Actions workflow will automatically:
   - Run all tests
   - Generate a changelog from commit messages
   - Create a GitHub release
   - Build and attach release artifacts
   - Update release notes with statistics

### Manual Method

1. **Update the version in package.json:**
   ```json
   {
     "version": "1.0.1"
   }
   ```

2. **Commit the change:**
   ```bash
   git add package.json
   git commit -m "chore: bump version to 1.0.1"
   ```

3. **Create and push a tag:**
   ```bash
   git tag -a v1.0.1 -m "Release v1.0.1"
   git push origin main
   git push origin v1.0.1
   ```

## Release Workflow

The release workflow (`release.yml`) performs the following actions:

1. **Validation:**
   - Runs linting checks
   - Runs all tests
   - Builds the site

2. **Changelog Generation:**
   - Extracts commits since the last tag
   - Groups changes by type (features, fixes, docs, etc.)
   - Formats according to conventional commits

3. **Release Creation:**
   - Creates a GitHub release with generated changelog
   - Includes statistics (test coverage, supported versions)
   - Provides installation instructions

4. **Asset Building:**
   - Creates source code archive (excluding build artifacts)
   - Creates pre-built site archive
   - Attaches both to the release

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** version: Incompatible API changes
- **MINOR** version: New functionality (backwards compatible)
- **PATCH** version: Bug fixes (backwards compatible)

## Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/) for clear changelogs:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `chore:` Maintenance tasks
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `style:` Code style changes
- `perf:` Performance improvements

## Post-Release

After a release:

1. Update any documentation that references the version
2. Announce the release (if applicable)
3. Monitor for any issues with the new release
4. Consider creating a GitHub Discussion for feedback

## Troubleshooting

If the release workflow fails:

1. Check the Actions tab for error messages
2. Ensure all secrets are properly configured
3. Verify that tests pass locally
4. Check that the tag format is correct (v1.0.0)

## Emergency Rollback

If a release has critical issues:

1. Create a new patch release with the fix
2. If immediate rollback is needed:
   ```bash
   git revert <commit-hash>
   python scripts/bump_version.py patch
   git push origin main
   git push origin v1.0.2  # New version
   ```