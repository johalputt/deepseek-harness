# Agent Note: scheduled security pipeline over shipped dependencies and history

Status: implemented

English | [中文](2026-08-25-security-pipeline.zh.md)

## Problem

The repository's CI (`ci.yml`) proves behavior on every pull request but has no standing scan for three risk classes that tests cannot catch: vulnerability announcements against already-merged dependencies (a Monday CVE drop never fails a green branch), secrets that entered git history before anyone noticed, and cross-file data-flow bugs (injection, SSRF-shaped flows, unsafe deserialization) that per-package unit suites structurally cannot see end to end. Coverage partitions, lockfile pinning, and credential hygiene reduce exposure but do not detect any of these classes.

## Decision

A separate `.github/workflows/security.yml` owns continuous security scanning, deliberately split from `ci.yml` so pull-request check panels stay behavioral (per the `.github` composition rule that keeps non-PR jobs out of PR circles):

1. **CodeQL** (`javascript-typescript`) analyzes the installed workspace graph — install precedes analysis so type-aware queries resolve workspace imports — and uploads SARIF to code scanning. Weekly schedule plus push/PR triggers.
2. **gitleaks** scans complete history on every trigger; a secret scrubbed from HEAD still leaks through older commits.
3. **`pnpm audit --prod --audit-level high`** gates on the production dependency graph using the committed lockfile directly (no install), so the audited artifact is exactly what ships.

The workflow runs on `ubuntu-latest` rather than the repository's Windows-first runner fleet: every job here is platform-independent static analysis with no product behavior under test, and `ubuntu-latest` keeps the pipeline functional on any fork that lacks the deployment's self-hosted pools and failover variables.

Threshold rationale: `high` is the audit floor because moderate ecosystem advisories accumulate too much noise to gate merges; a gate that people disable is not a gate. Production-only scoping keeps dev-tool advisories visible in PR review without blocking releases.

## Alternatives considered

**Why not extend `ci.yml` with these jobs?** The `.github` composition rule keeps master-only lanes out of `ci.yml` precisely so PR check circles show only what a PR should gate. Security scanning has a different trigger surface (weekly cron, history-wide) and different failure semantics (advisory-driven, sometimes fixed by a bump rather than a code change); folding it in would either put cron-only jobs into every PR panel or split triggers confusingly across one file.

**Why not Dependabot alerts alone?** Dependabot flags vulnerable *resolutions* in the manifest view but does not gate a merge, does not scan history for leaked secrets, and does no data-flow analysis. The pipeline composes with Dependabot (which already runs here); it does not replace it.

**Why not `--audit-level moderate` for stricter gating?** Audited strictly, the JavaScript ecosystem produces enough moderate advisories (often unreachable code paths or disputed reports) that the job would be disabled within weeks. High-and-above with production scope is the level this repository can sustain failing loudly forever.
