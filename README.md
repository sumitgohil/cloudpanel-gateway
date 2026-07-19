# CloudPanel Gateway

CloudPanel Gateway is a security-focused automation control plane for
CloudPanel. It gives operators, platform teams, CI systems, and AI agents one
safe way to manage and operate CloudPanel through a scoped REST API, a
Streamable HTTP MCP server, and a root-only local administration CLI.

It preserves CloudPanel compatibility through a typed `clpctl` adapter, then
adds policy-controlled operational capabilities CloudPanel does not natively
provide: diagnosis-ready logs, managed releases and deployments, hardened Node
runtime services, encrypted backups, TLS health, and site-scoped cron jobs.
It never exposes an arbitrary remote shell or generic command runner.

> This is an independent project and is not affiliated with CloudPanel.

## Highlights

- One statically compiled Go binary for Linux `amd64` and `arm64`.
- Three automation interfaces with one authorization model: authenticated REST
  (`/v1`) for platforms and CI, Streamable HTTP MCP (`/mcp`) for AI clients,
  and a root-only CLI for local operator control.
- Opaque bearer tokens with keyed hashes at rest, scopes, expiry, rotation,
  revocation, last-use tracking, and durable redacted auditing.
- A non-networked root helper that accepts only versioned, typed requests and
  executes CloudPanel-compatible actions through argument arrays—never a
  shell.
- A separate root-only Nginx validation/commit service for settings changes.
- Safe CloudPanel administration for sites, users, databases, certificates,
  Varnish, Cloudflare, and vhost templates.
- Read-only site log investigation and deterministic diagnostics for Nginx,
  PHP, rotated logs, and common framework application logs.
- Revision-guarded site-root, PHP, PageSpeed, and site-user password controls.
- Read-only TLS inspection plus MCP chunked ZIP uploads, policy-gated
  deployments, and encrypted local site backups with safety backups.
- Static/Vite/Astro delivery, Node/SSR release management through hardened
  per-site systemd units, and CloudPanel-compatible site cron jobs.

## Quick start

Prerequisites: a supported CloudPanel installation on Ubuntu 24.04, `clpctl`,
root access, and an FQDN that resolves to the server.

1. Download the release-pinned installer. It fetches the signed
   architecture-specific binary and verified systemd unit templates, verifies
   their SHA-256 checksums and Minisign signatures, then installs the gateway.

   ```bash
   VERSION=<release-version>; DIR="$(mktemp -d)"; curl --fail --location --proto '=https' --tlsv1.2 -o "$DIR/cloudpanel-gateway-install.sh" "https://github.com/sumitgohil/cloudpanel-gateway/releases/download/v${VERSION}/cloudpanel-gateway-install.sh" && curl --fail --location --proto '=https' --tlsv1.2 -o "$DIR/cloudpanel-gateway-install.sh.minisig" "https://github.com/sumitgohil/cloudpanel-gateway/releases/download/v${VERSION}/cloudpanel-gateway-install.sh.minisig" && sudo apt-get update && sudo apt-get install --yes --no-install-recommends minisign && minisign -Vm "$DIR/cloudpanel-gateway-install.sh" -P 'RWSc0fp65r6GcJiRAcydy1W60Jk8kvusaJyijgESv0WLwPaEd15sohP/' && sudo bash "$DIR/cloudpanel-gateway-install.sh" --version "${VERSION}"
   ```

   Replace `<release-version>` with the release you intend to install. The
   first release containing the standalone installer is required for this path.
   It verifies the installer before executing it; the installer then verifies
   the binary and unit templates. Checked-out release installation remains
   available below and for earlier releases.

2. Read and immediately secure the one-time bootstrap token:

   ```bash
   sudo cat /root/cloudpanel-gateway-bootstrap-token.txt
   sudo rm /root/cloudpanel-gateway-bootstrap-token.txt
   ```

3. Map the public gateway hostname, then explicitly issue TLS:

   ```bash
   sudo cloudpanel-gateway domain map --domain panel.example.com --expected-ip 203.0.113.10
   sudo cloudpanel-gateway domain tls issue --domain panel.example.com
   ```

4. Create a least-privilege token for a client. Plaintext tokens are shown only
   at creation or rotation time.

   ```bash
   sudo cloudpanel-gateway token create \
     --label developer-agent \
     --scopes 'sites:read,sites:write,logs:read,php:read,php:write,pagespeed:read,pagespeed:write,cache:purge,certificates:write,tls:read,artifacts:write,files:write,backups:read,backups:write,node:read,node:write,node:deploy,node:build'
   ```

See [installation](docs/installation.md), [usage](docs/usage.md), and
[REST and MCP](docs/api-mcp.md) for the complete guide.

## What CloudPanel Gateway is

CloudPanel remains the hosting platform: it owns sites, users, TLS, Nginx, and
its supported language runtimes. Gateway is the secure automation layer around
those primitives. Its CloudPanel adapter invokes only a fixed, typed catalog of
compatible operations; its gateway-native capabilities add controlled release
delivery, runtime lifecycle management, diagnostics, backup, and scheduling.

This is not a replacement for the CloudPanel UI, nor a generic remote server
administration API. It is an independent, least-privilege control plane for
automating well-defined hosting operations safely.

## Architecture and safety model

The public service runs as the non-login `cloudpanel-gateway` user and listens
on loopback by default. A reverse proxy created through CloudPanel exposes it
on a mapped FQDN. The privileged helper listens only on a restricted Unix
socket; it validates every typed action a second time before invoking `clpctl`.
There is no generic command runner in either the REST API or MCP server.

Settings changes use a separate root-only commit socket. It accepts generated,
validated vhost content only, runs `nginx -t`, reloads Nginx after success, and
rolls back configuration if validation or reload fails. The public service and
the main helper keep `NoNewPrivileges=true` and
`MemoryDenyWriteExecute=true`. The isolated Nginx commit service disables only
the latter because CloudPanel's `ngx_pagespeed` module requires an executable
stack when Nginx validates its configuration.

High-risk operations are disabled by server policy until an administrator
enables them locally. A token still needs its matching scope after policy is
enabled. Read [the security model](docs/security.md) before production use.

## Capabilities

| Area | What is available |
| --- | --- |
| Sites | Create static, PHP, Node.js, Python, and reverse-proxy sites; delete sites; issue Let's Encrypt certificates; install policy-gated manual certificates. |
| Users | Create, list, delete, reset passwords, and disable MFA for CloudPanel users. |
| Databases | Create/delete databases plus policy-gated master credential and import/export operations using managed artifacts. |
| CloudPanel administration | Basic auth and release-channel controls; Cloudflare IP updates; Varnish purge; and vhost-template management through typed compatibility actions. |
| Site settings | Site facts/TLS/drift, guarded root directory update, one-time site-user password rotation, safe PHP limits/directives, and PageSpeed controls. |
| Logs | Source discovery, bounded queries, redaction, gzip rotation support, and deterministic diagnosis signals. |
| Delivery and recovery | TLS health inspection, MCP-managed ZIP upload/deployment, and encrypted files/databases backups retained locally for seven days (10 GiB total). |
| Application hosting | Static/Vite/Astro releases, optional SPA fallback routing, and policy-gated Node.js/SSR releases managed by hardened per-site systemd units. |
| Scheduling | CloudPanel-compatible, site-scoped schedules with typed PHP, Node.js, executable, and same-domain HTTPS runners; raw commands remain locally policy-gated. |

The exact request schema is published by the running gateway at `/openapi.json`.
The MCP server describes its typed tools during tool discovery.

## Local CLI

All state-changing local administration commands require root. Discover the
current command surface rather than relying on copied flags:

```bash
sudo cloudpanel-gateway --help
sudo cloudpanel-gateway token --help
sudo cloudpanel-gateway settings --help
sudo cloudpanel-gateway completion zsh > "${fpath[1]}/_cloudpanel-gateway"
sudo cloudpanel-gateway doctor
```

Important command groups:

- `token create|list|revoke|rotate`
- `policy enable|disable|list`
- `domain map|adopt|status|unmap|tls issue`
- `settings site settings|root|user rotate-password`
- `settings php get|update`
- `settings pagespeed get|update|purge`
- `tls status`, `file deploy-artifact`, and `backup create|list|restore`
- `node settings|status|update-settings|deploy-release|releases|rollback|restart`
- `doctor`, `service`, `version`, and `completion`

## REST and MCP

Every non-health endpoint requires `Authorization: Bearer cp_live_...`.
MCP is served at `https://<mapped-domain>/mcp` over Streamable HTTP. A minimal
Codex-compatible configuration is:

```toml
[mcp_servers.cloudpanel-gateway]
url = "https://panel.example.com/mcp"
bearer_token_env_var = "CLOUDPANEL_GATEWAY_TOKEN"
```

Do not put the token directly in the configuration file or commit it. Set it in
the environment of the MCP client. Details, endpoints, scopes, tools, and
examples are in [docs/api-mcp.md](docs/api-mcp.md).

## Development

```bash
go test ./...
go vet ./...
go build ./cmd/cloudpanel-gateway
```

For the disposable test VM only, `install.sh --local-binary /path/to/binary`
skips release download verification. It is deliberately unsuitable for a
production install.

## Contributing and support

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request,
[SECURITY.md](SECURITY.md) for private vulnerability reporting, and
[SUPPORT.md](SUPPORT.md) for usage questions. Issue templates are provided for
bugs and feature proposals. Maintainers should follow the
[maintainer checklist](docs/maintainers.md).

## License

Copyright 2026 CloudPanel Gateway contributors.

Licensed under the [Apache License, Version 2.0](LICENSE).
