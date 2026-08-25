# Agent Note: web-fetch-http private-network destination blocking

Status: implemented

English | [中文](2026-08-25-web-fetch-ssrf-blocking.zh.md)

## Problem

`@deepseek-ai/dsh-web-fetch-http` shipped as a deliberately deferred SSRF primitive: it validated URL shape (http/https-only, no embedded credentials, length caps) but nothing about *where the name resolves*. A model-supplied URL could therefore direct harness egress at loopback services, RFC1918/LAN hosts, or the cloud metadata endpoint `169.254.169.254` — the classic server-side request forgery path, made sharper because the fetcher runs on developer machines and CI runners that legitimately hold credentials.

The [web capability seam Agent Note](2026-06-24-web-capability-seam.md) named this gap as its top deferred item and set the bar: DNS-resolve-then-validate to defeat rebinding, per-hop re-validation across redirects, IPv6 edge handling including embedded-IPv4 forms. Neither surveyed reference implementation did IP-level blocking (OpenCode prefix-checks the hostname string; Claude Code relies on a centralized hostname blocklist plus a prompt), so there was nothing to copy.

A string check on the hostname was never enough. `localhost`, `127.0.0.1`, and `[::1]` are trivial; an attacker-controlled authoritative DNS server can answer with a public address during validation and a private one at connection time (DNS rebinding / TOCTOU); and IPv4 can hide inside IPv6 spellings (`::ffff:10.0.0.5`, 6to4, NAT64) that a v4-only blocklist never sees.

## Decision

The provider gains `blockPrivateNetworks` (plugin `Config` default **true**; required field on `HttpFetchLimits` so direct consumers state their choice explicitly). When enabled:

1. **Per-hop pre-flight** (`private-net.ts` → `assertPublicHost`): before every request (including each redirect target), literal IPs are judged directly and hostnames are resolved through the platform resolver with `{ all: true }`; if *any* resolved address is non-public, the hop fails fast with `WEB_PRIVATE_NETWORK` before any socket exists.
2. **Connect-time re-validation**: when blocking is on, requests go through an undici `Agent({ connect: { lookup } })` whose lookup re-validates whatever addresses the socket may actually open. A resolution change between pre-flight and connect still loses; this closes the rebinding window rather than narrowing it.
3. **All-answers semantics**: one non-public answer among several rejects the whole name, so a hostile authoritative server cannot hide a private record behind a public front.

Classification (`isPubliclyRoutableAddress`) judges IPv4 against loopback, 0/8, 10/8, CGNAT 100.64/10, link-local 169.254/16, private 172.16/12 and 192.168/16, IETF protocol assignments, deprecated 6to4 relay anycast, benchmarking 198.18/15, TEST-NET documentation ranges, multicast 224/4, and reserved/broadcast space. IPv6 is parsed to its eight groups (`::` compression, single dotted tail, zone stripping), then checked for unspecified/loopback, unique-local fc00::/7, link-local fe80::/10, multicast ff00::/8, documentation 2001:db8::/32 — while IPv4-mapped `::ffff:0:0/96`, NAT64 `64:ff9b::/96`, and 6to4 `2002::/16` are unwrapped and judged by their embedded IPv4 self. Unparsable input fails closed.

Two grammar details carry security weight and are pinned by tests: a dotted-decimal tail is legal only as the final component of the whole address (so `10.0.0.1::` does not parse into an unrelated "public" v6 address), and under `::` compression only after the marker.

The refusal is config-owned, not hardcoded policy: `blockPrivateNetworks: false` restores plain ambient fetching byte-for-byte, which is what deployments pointing the model at loopback dev servers need — and what this package's own fixture suites use.

### What remains out of scope

The fence trusts the platform resolver: names the OS resolves outside `getaddrinfo` (e.g. mDNS), or proxy deployments whose CONNECT target is never resolved locally, bypass the check. Those shapes need deployment-level egress policy, not provider code.

## Alternatives considered

**Why not a hostname-string blocklist (the OpenCode/Claude Code shape)?** It only catches spellings, not destinations: `localhost.internal.example.com` resolving to `10.0.0.9`, or any rebinding record, sails through. The decision in the seam note explicitly demanded resolve-then-validate; a string list would be a speed bump labeled a fence.

**Why not resolve once, validate, then connect to the validated IP?** Rewriting the URL to the validated address changes the wire request (`Host` header vs. SNI/certificate identity) or needs per-scheme pinning machinery; and the window between validation and use still exists unless the rewrite is repeated per redirect. The dispatcher-level lookup achieves the same TOCTOU immunity on Node's own connection path with no URL rewriting and no certificate-identity drift.

**Why undici instead of patching global `fetch` options?** Node's ambient `fetch` accepts a `dispatcher` RequestInit field only as an unofficial extension; undici's own `fetch` documents the option. Using undici for the blocked path keeps the control on a contractually supported surface, and the unblocked path stays byte-identical to today's global fetch.

**Why default-on instead of opt-in hardening?** This is the harness's only SSRF defense, and the safe default matches the seam note's standing rule ("must not be enabled where it can reach sensitive internal targets") without requiring every deployment to know the risk exists. Deployments that genuinely need private targets have a one-line, documented opt-out — misconfiguration then fails loud (`WEB_PRIVATE_NETWORK`) rather than silently opening the network.
