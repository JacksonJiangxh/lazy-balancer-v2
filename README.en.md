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
| Branches | `master` | `main` (mainline), `master` (upstream mirror track, GitHub only) |
| Image | Docker Hub `v55448330/...` | CNB registry `docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest` |
| Feedback | Upstream issues | Issues in this repo |

### Branches

| Branch | Where | Purpose |
|---|---|---|
| `main` | CNB + GitHub | **Mainline.** Upstream baseline plus all our changes |
| `master` | GitHub only | **Upstream mirror track.** Auto-synced to an upstream release by GitHub Actions, byte-for-byte identical to that tag. **No development here.** |
| `master-dev` | GitHub only | GitHub's default branch, kept in sync with our `main` |

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
  --build-arg VERSION=v2.3.4 \
  --provenance=false --sbom=false \
  -t docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest --push .
```

CI runs on the CNB pipeline: click the "Build & Push Image" button on the main
branch page to trigger a native amd64/arm64 dual-arch build → real container
smoke test → push to the CNB registry
`docker.cnb.cool/xzydm/lazy-balancer-v2` (both `latest` and a versioned
manifest), then mirror the `latest` multi-arch image into
`docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2`. Config lives in `.cnb.yml`
and `.cnb/web_trigger.yml`.

> The official Docker Hub `v55448330/lazy-balancer-v2` is **upstream's** image
> and does not contain our changes. Do not reference it in this repo's
> deployment flow.
</details>

## What we changed versus upstream

A plain-language view; the file-by-file reconciliation is in the
[upstream merge checklist](docs/upstream-merge.zh-CN.md).

| Change | Description |
|---|---|
| Chained fallback strategy | Fall back to the next upstream group when a whole group is down or all-404, without leaking backend error bodies |
| Referenced certificate ingestion | `tls_source=file` now reads PEM into the DB on save, making the DB the single source of truth; external file changes are written back and hot-reloaded by a watchdog |
| Port remapping | `HTTP_PORT` / `HTTPS_PORT` / `PANEL_PORT` officially remap listen ports; default semantics only, existing rules untouched |
| Custom-route origin Host | Origin Host for custom-route upstreams is derived internally at render time — **no new fields in the rule editor** |
| Referenced cert update fix | Fixes referenced cert file sources being wrongly rejected on rule update |
| Upstream release watch | A CNB scheduled job checks for new upstream releases and opens an issue when one appears |

## How upstream sync works

Three gates, each with one job:

1. **GitHub Actions** (`sync-upstream-master.yml`)
   Checks upstream tags every 6 hours (only `v<major>.<minor>.<patch>` release
   tags), and syncs its commit to the fork's `master` when a new one appears.
   Requires the repository secret `UPSTREAM_SYNC_TOKEN` (a PAT with repo scope).

2. **CNB scheduled job** (the `crontab` entry under `main` in `.cnb.yml`)
   Checks the latest upstream version every 6 hours; if it is newer than
   `BASELINE_TAG` it opens an issue. One issue per version, no spam.

3. **Manual merge**
   After the issue, follow the
   [upstream merge checklist](docs/upstream-merge.zh-CN.md): produce a diff
   list → you decide → we change code → bump `BASELINE_TAG` → close the issue.

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
| 2026-10-11 | Port remap edge cases; custom-route origin Host derived at render time; referenced certificate ingestion; chained fallback strategy; GitHub Actions upstream sync + CNB upstream watch; README rewrite; `docker-compose` now references our own image |

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
