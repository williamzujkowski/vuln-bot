Design and stand-up an end-to-end “Morning Vuln Briefing” platform that:

Harvests & ranks fresh vulnerability intel every night

Pulls CVE 4.0 records, EPSS, GitHub Advisory, OSV, Libraries.io, plus Red Hat/MSRC/Talos and other vendor feeds.

Normalises them, calculates a weighted Risk Score 0-100 (CVSS, EPSS, popularity, infra tags, newness).

Caches responses in SQLite via actions/cache (10-day TTL) to stay within API quotas.

Publishes machine-readable artefacts + human-readable blog post

Generates _posts/{{date}}-vuln-brief.md (Nunjucks template, flattened front-matter) and trimmed JSON detail files at /api/vulns/{{cveId}}.json (vector, CPEs, refs, ATT&CK mappings).

Builds a thin /api/vulns/index.json containing the consolidated search index.

Drives a client-side, filter-first analyst UI that is the blog home page

11ty (input src/, output public/) → pushed to gh-pages/public.

Alpine.js (UI) + Fuse.js (search) power instant filtering on title, summary, CVE ID, severity, CVSS slider (0-10 in 0.1 steps), EPSS slider (0-100), date-range, vendor, priv-req, user-interaction, exploitation status, arbitrary tags; sortable column headers; paginated 10/20/50/100 rows.

State stored in URL hash for shareable views.

Automated CI/CD & quality gates

Nightly workflow (main → build → publish → commit artifacts back to main, deploy built site to gh-pages/public).

Branch CI: ubuntu-latest matrix runs Ruff (F*/E* fail), pytest-cov (≥ 80 %), Bandit & TruffleHog (high+ severities fail), CodeQL (security suite, JS+Py), npm-audit (high+ fail), commitlint, ESLint(Google)+Prettier via Husky pre-commit, cached Node deps (7 days).

Coverage badge (Shields.io) auto-rewrites at top of README; HTML report stored as 90-day artifact.

Feature-flagged Slack/Teams alert job gated by SEND_ALERTS=false + webhook secret.

Infrastructure & tooling

Python 3.x (floating), uv for deps + lockfile committed; Node latest LTS; ruff config in pyproject.toml; Husky + lint-staged; MIT license.

Secrets: GH_ADVISORY_TOKEN, LIBRARIES_IO_KEY, MSRC_API_KEY, NVD_API_KEY, CVE_API_KEY; built-in GITHUB_TOKEN (contents write) handles pushes.

Net result: every morning main gains a new Markdown brief, JSON index refresh, and coverage-badge update; gh-pages serves an 11ty site whose landing page is a fast, fully client-side vulnerability dashboard analysts can search, sort, and share instantly—no backend servers, no manual steps, high security hygiene, and ready for future Slack alerts or extra data feeds.