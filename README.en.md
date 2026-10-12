# Lazy Balancer V2 · Self-maintained Fork

English | [简体中文](README.md)

> **This is not the upstream project.** This is a **self-maintained fork** of
> [v55448330/lazy-balancer-v2](https://github.com/v55448330/lazy-balancer-v2):
> we layer our own fixes and enhancements on top of upstream, and merge
> upstream releases on our own schedule.

A visual load balancing platform built on **Caddy v2.11**, with a full WAF
security stack, delivered as a single container.

## What this repository is

In one line: **upstream's capabilities, plus fixes for the problems we actually hit.**

We run this in production. When something breaks we fix it and keep the fix
here. So the relationship with upstream is "same origin, diverged, periodically
re-synced":

| | Upstream | This repo |
|---|---|---|
| Purpose | Official releases | Production use + customizations |
| Versioning | Official tags | Tracks upstream tags; our changes ship anytime |
| Branches | `master` | `master-dev` (mainline), `master` (upstream mirror track) |
| Image | Docker Hub `v55448330/...` | `docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest` |
| Feedback | Upstream issues | Issues in this repo |

### Branches

| Branch | Where | Purpose |
|---|---|---|
| `master-dev` | Default branch of this repo | **Mainline.** Upstream baseline plus all our changes |
| `master` | This repo | **Upstream mirror track.** Auto-synced to an upstream release by GitHub Actions, byte-for-byte identical to that tag. **No development here.** |

> Why keep a clean `master`: "how far behind upstream are we" then has exactly
> one reference point, never polluted by our own changes. The scheduled watch
> job relies on it too.

## Quick Start

```bash
docker run -d --name lazy-balancer --network host \
  --ulimit nofile=1048576:1048576 \
  -v $(pwd)/data:/app/data -v $(pwd)/certs:/app/certs \
  -v $(pwd)/logs:/app/logs -v $(pwd)/waf:/app/waf \
  -v $(pwd)/backup:/app/backup \
  docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest
```

Mounts: `/app/data` database and config (required), `/app/certs` certificates
and private keys (required), `/app/backup` auto-backup output directory
(required — without it, backups are lost when the container is recreated),
`/app/logs` logs (recommended), `/app/waf` rule sets and GeoIP (recommended).

Open `http://localhost:8000` for the admin panel. First visit opens an
initialization wizard; no default credentials.

> Docker Desktop (macOS/Windows): use a named volume for `/app/data`
> (`-v lb-data:/app/data`). Bind mounts over the FUSE shared layer risk SQLite
> WAL page loss (not an issue for bind mounts on a Linux host).

> If ports 80/443/8000 are taken, remap them with `HTTP_PORT` / `HTTPS_PORT` /
> `PANEL_PORT` (with host networking these are the actual listen ports). See the
> [deployment guide](docs/deployment.zh-CN.md). Existing rules keep their stored
> ports — update and save them manually.

<details>
<summary>Docker Compose / Build from Source</summary>

```bash
# Docker Compose — the image in the compose file already points at our registry
docker compose up -d

# Build from source
# The frontend is produced by the node build stage inside the Dockerfile,
# so there is no need to run npm build locally first
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=v2.3.5 \
  --provenance=false --sbom=false \
  -t docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest --push .
```

Images are built by an internal pipeline and published as
`docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2`: multi-arch build, real-container
smoke test, then both a `latest` and a versioned manifest.

> The official Docker Hub `v55448330/lazy-balancer-v2` is **upstream's** image
> and does not contain our changes. Do not reference it in this repo's
> deployment flow.
</details>

## What we changed versus upstream

**Current upstream baseline: `v2.3.6-beta` (`c617664b`, covering the 11 commits after `v2.3.5`).** Everything upstream
shipped in that release (native `map` late-binding for origin domains,
`response_mode` tri-state for static responses, health-check host, SNI port
stripping, dashboard quantile interpolation, the 151-item round-69 audit, etc.)
is already merged in — see the
[upstream merge checklist](docs/upstream-merge.zh-CN.md) for the itemized
reconciliation.

The table below lists only capabilities **unique to us** (not in upstream):

| Change | Description |
|---|---|
| Chained fallback strategy | Fall back to the next upstream group when a whole group is down or all-404, without leaking backend error bodies |
| Referenced certificate ingestion | `tls_source=file` now reads PEM into the DB on save, making the DB the single source of truth; external file changes are written back and hot-reloaded by a watchdog |
| Port remapping | `HTTP_PORT` / `HTTPS_PORT` / `PANEL_PORT` officially remap listen ports; default semantics only, existing rules untouched |
| Referenced cert update fix | Fixes referenced cert file sources being wrongly rejected on rule update |
| Upstream release watch | A scheduled job checks for new upstream releases and opens an issue when one appears |

## How upstream sync works

Three gates, each with one job:

1. **GitHub Actions** (`sync-upstream-master.yml`)
   Checks upstream tags every 6 hours (only `v<major>.<minor>.<patch>` release
   tags), and syncs its commit to this repo's `master` when a new one appears.
   Requires the repository secret `UPSTREAM_SYNC_TOKEN` (a PAT with repo scope).

2. **Release watch**
   A scheduled job compares the latest upstream version against the maintained
   baseline and opens an issue when a new one appears. One issue per version,
   no spam.

3. **Manual merge**
   After the issue, follow the
   [upstream merge checklist](docs/upstream-merge.zh-CN.md): produce a diff
   list → decide → change code → bump the baseline → close the issue.

## Documentation

| Document | Contents |
|---|---|
| [Upstream merge checklist](docs/upstream-merge.zh-CN.md) (中文) | Divergence reconciliation, open decisions, merge order |
| [Deployment](docs/deployment.zh-CN.md) (中文) | Mounts, environment variables, ports, production flags |
| [Security](docs/security.zh-CN.md) (中文) | WAF policies, IP control, event collection, rule updates |
| [Cluster](docs/cluster.zh-CN.md) (中文) | Primary-replica architecture, MFA, security model, upgrades |
| [OIDC Login](docs/oidc.zh-CN.md) | Enterprise SSO via OIDC, Entra example (Chinese) |
| [Production Tuning](docs/production-tuning.zh-CN.md) (中文) | Five-layer tuning: kernel/container/LB/WAF/HTTP3 |
| [API Reference](docs/api.zh-CN.md) (中文) | REST endpoints, authentication, error codes |
| [MCP Service](docs/mcp.zh-CN.md) (中文) | AI agent integration, tool permissions, workflows |

## Features

| Feature | Description |
|---|---|
| Load Balancing | HTTP/HTTPS/TCP L4 proxy, multiple strategies, health checks, path routing |
| WAF Security | OWASP CRS + custom rules + IP control + GeoIP blocking + rate limiting |
| Free Certificates | ACME auto-issuance (DNS-01), auto-renewal |
| Primary-Replica Cluster | Incremental sync, tamper-proof signatures, read-only replicas, one-click promotion |
| Monitoring | Traffic/latency P50-P99, upstream health, security event dashboard |
| MCP Service | AI agents can operate all features via tools |
| Auto Backup | Scheduled daily/weekly/monthly config backups, one-click restore |

## Changelog

Our own iterations, newest first. Upstream version changes are in upstream's
releases.

| Date | Content |
|---|---|
| 2026-10-12 | **Caught up the 11 untagged upstream commits after `v2.3.5`** (through `v2.3.6-beta` / `c617664b`): Caddy v2.11.7 streaming-forwarding regression fix, Go 1.26.9 + x/net v0.60.0 + Alpine 3.24.2 (10 CVEs), coraza v3.8.1 security fixes, a new rule-level NTLM compatibility switch, round 70/71 audit fixes, task-engine state-column plan A — a security/regression-grade update; our self-maintained features (chained fallback, referenced-cert ingestion, port remapping) and the rule-level `origin_domain` naming are preserved |
| 2026-10-11 | **Merged upstream v2.3.5** (`98c607ac`): per-upstream origin domain now uses upstream `origin_domain` + native `map`, static responses use upstream `response_mode` tri-state — our `host_header` / `action=respond` implementations retired, with automatic two-way data migration; chained fallback, referenced-cert ingestion and port remapping kept |
| 2026-10-11 | Port remap edge cases; referenced certificate ingestion; chained fallback strategy; GitHub Actions upstream sync + release watch; README rewrite; `docker-compose` now references our own image |
| 2026-10-11 | Removed references to the internal development platform (footer link, CI section, migration notes); public surface now points at this repo |

## Tech Stack

Go 1.26 · Gin · SQLite · Caddy v2.11 · Coraza v3 · OWASP CRS v4 · Vue 3 · Element Plus

## License

Upstream is licensed under the [Apache License 2.0](LICENSE). This repo follows
the same license.

As Apache-2.0 requires, our modifications to upstream code are itemized in this
repository's commit history and in the
[upstream merge checklist](docs/upstream-merge.zh-CN.md).
This repo **removes the upstream community QQ group QR code and group number**
from the README (that is upstream's community entry point, not ours), and keeps
upstream's LICENSE and copyright notices intact.
