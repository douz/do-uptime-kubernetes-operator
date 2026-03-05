# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

## How We Track Changes

- This project does not require tag-based GitHub releases for publishing.
- Artifacts are published from `main`:
  - Docker images: `ghcr.io/douz/do-uptime-kubernetes-operator` (`latest` and commit SHA tags)
  - Helm charts: published to `https://charts.douz.io`
- Keep `## [Unreleased]` updated in PRs and move entries to a dated section when changes are merged.
- For chart/runtime changes, bump chart metadata in `charts/do-uptime-operator/Chart.yaml` and reflect it in this file.

## [Unreleased]

## [0.1.0] - 2026-03-05

### Added
- Initial public open-source baseline for the DigitalOcean Uptime Monitor Operator.
- Governance and community health files (`CONTRIBUTING`, `CODE_OF_CONDUCT`, `SECURITY`, `SUPPORT`, `MAINTAINERS`).
- GitHub issue templates, PR template, CODEOWNERS, and Dependabot config.
- GitHub Pages landing site at `do-uptime-operator.douz.io`.
