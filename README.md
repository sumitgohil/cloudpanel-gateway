# CloudPanel Gateway

CloudPanel Gateway is a security-focused Go service that turns the CloudPanel
`clpctl` command line into a scoped REST API, a Streamable HTTP MCP server, and
a root-only local administration CLI. It is designed for operators and AI
clients that need useful CloudPanel automation without exposing arbitrary shell
or `clpctl` execution to the network.

> This is an independent project and is not affiliated with CloudPanel.

## Highlights

- One statically compiled Go binary for Linux `amd64` and `arm64`.
- Authenticated REST (`/v1`), OpenAPI (`/openapi.json`), docs (`/docs`),
  metrics (`/metrics`), and MCP Streamable HTTP (`/mcp`).
- Opaque bearer tokens with keyed hashes at rest, scopes, expiry, rotation,
  revocation, last-use tracking, and durable redacted auditing.
- A non-networked root helper that accepts only versioned, typed requests and
  executes a fixed allowlist through argument arrays—never a shell.
- A separate root-only Nginx validation/commit service for settings changes.
- Safe CloudPanel site, user, database, certificate, Varnish, Cloudflare, and
  vhost-template operations.
- Read-only site log investigation and deterministic diagnostics for Nginx,
  PHP, rotated logs, and common framework application logs.
- Revision-guarded site-root, PHP, PageSpeed, and site-user password controls.
- Read-only TLS inspection plus MCP chunked ZIP uploads, policy-gated
  deployments, and encrypted local site backups with safety backups.

## Quick start

Prerequisites: a supported CloudPanel installation on Ubuntu 24.04, `clpctl`,
root access, and an FQDN that resolves to the server.

1. Download this repository at the release you intend to install. The release
   installer downloads the signed architecture-specific binary, verifies its
   SHA-256 checksum and Minisign signature, and installs the included units.

   ```bash
   git clone https://github.com/sumitgohil/cloudpanel-gateway.git
   cd cloudpanel-gateway
   git checkout v0.1.0
   sudo ./install.sh --version 0.1.0
   ```

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
| CloudPanel | Basic auth and release channel controls; Cloudflare IP updates; Varnish purge; vhost-template management. |
| Site settings | Site facts/TLS/drift, guarded root directory update, one-time site-user password rotation, safe PHP limits/directives, and PageSpeed controls. |
| Logs | Source discovery, bounded queries, redaction, gzip rotation support, and deterministic diagnosis signals. |
| Recovery | TLS health inspection, MCP-managed ZIP upload/deployment, and encrypted files/databases backups retained locally for seven days (10 GiB total). |
| Applications | Static/Vite/Astro releases, optional SPA fallback routing, and policy-gated Node.js/SSR releases managed by hardened per-site systemd units. |
| Cron jobs | CloudPanel-compatible, site-scoped schedules with typed PHP, Node.js, executable, and same-domain HTTPS runners; raw commands remain locally policy-gated. |

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
