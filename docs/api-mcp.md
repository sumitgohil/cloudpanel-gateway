# REST API and MCP

The public gateway uses bearer authentication for every endpoint except
`/healthz` and `/readyz`. Do not expose the loopback listener directly; map a
TLS-enabled CloudPanel reverse proxy first.

## REST endpoints

| Endpoint | Required scope |
| --- | --- |
| `GET /healthz`, `GET /readyz` | None |
| `GET /openapi.json`, `GET /docs` | `docs:read` |
| `GET /metrics` | `metrics:read` |
| `POST /v1/sites` | `sites:write` |
| `POST /v1/actions/{action}` | Action-specific scope |
| `POST /v1/artifacts` | `artifacts:write` |
| `GET /v1/sites/{domain}/logs/sources` | `logs:read` |
| `POST /v1/sites/{domain}/logs/query` | `logs:read` (`raw` needs `admin`) |
| `POST /v1/sites/{domain}/logs/diagnose` | `logs:read` |
| `GET /v1/sites/{domain}/settings` | `sites:read` |
| `PATCH /v1/sites/{domain}/settings/root-directory` | `sites:write` |
| `POST /v1/sites/{domain}/settings/site-user/password/rotate` | `site-users:write` |
| `GET` / `PATCH /v1/sites/{domain}/php` | `php:read` / `php:write` |
| `GET` / `PATCH /v1/sites/{domain}/pagespeed` | `pagespeed:read` / `pagespeed:write` |
| `POST /v1/sites/{domain}/pagespeed/purge` | `cache:purge` |
| `GET /v1/sites/{domain}/tls` | `tls:read` |
| `POST /v1/sites/{domain}/deployments` | `files:write` + `file.deploy_artifact` policy |
| `GET` / `POST /v1/sites/{domain}/backups` | `backups:read` / `backups:write` |
| `POST /v1/sites/{domain}/backups/{backup_id}/restore` | `backups:write` + `backup.restore` policy + `confirm:true` |

Example:

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $CLOUDPANEL_GATEWAY_TOKEN" \
  https://panel.example.com/v1/sites/app.example.com/settings
```

The OpenAPI document on the running service is authoritative for JSON request
and response schemas. Responses include an `X-Request-ID`; include one in a
support request when reporting an issue.

## Typed CloudPanel actions

`POST /v1/actions/{action}` takes a JSON object with an `args` map. Only the
following actions are accepted: `cloudflare.update_ips`, CloudPanel basic-auth
and release-channel controls, database create/delete/import/export/master
credentials, Let's Encrypt/manual certificate operations, all supported site
types and site deletion, permission reset, CloudPanel user management,
vhost-template management, and Varnish purge.

The complete, version-specific action names, fields, and policy requirements
are exposed through `/openapi.json` and MCP tool discovery. There is no
arbitrary `clpctl` endpoint.

## MCP

The MCP endpoint is `/mcp` using Streamable HTTP. It accepts the same bearer
token and validates browser Origins against localhost, configured allowed
hosts, and mapped gateway domains.

```toml
[mcp_servers.cloudpanel-gateway]
url = "https://panel.example.com/mcp"
bearer_token_env_var = "CLOUDPANEL_GATEWAY_TOKEN"
```

In addition to a typed MCP tool for each allowed CloudPanel action, the gateway
provides these named tools:

- `cloudpanel_site_logs_list_sources`
- `cloudpanel_site_logs_query`
- `cloudpanel_site_logs_diagnose`
- `site_get_settings`
- `site_update_root_directory`
- `site_rotate_user_password`
- `php_get_settings`, `php_update_settings`
- `pagespeed_get_settings`, `pagespeed_update_settings`,
  `pagespeed_purge_cache`
- `tls_get_status`
- `file_deploy_artifact`
- `site_backup_create`, `site_backup_list`, `site_backup_restore`

Tools return structured JSON. A log diagnosis offers deterministic evidence
such as HTTP error rates, upstream failures, PHP fatal/timeout/memory errors,
permission failures, missing files, and common database connection errors. It
does not apply a fix.

## Managed artifacts

Database transfer, manual certificate, and vhost-template file inputs must be
created through `POST /v1/artifacts`. The gateway stores them in a restricted
directory and expires them after one hour. User-supplied absolute file paths,
shell snippets, and arbitrary Nginx/PHP/PageSpeed directives are rejected.

ZIP deployments use the same managed artifact flow, but accept only validated
ZIP archives up to 100 MiB compressed. Archive traversal, duplicate entries,
symlinks, devices, and excessive expansion are rejected. The target directory
must be relative to the resolved site root; replacing non-empty content needs
both `replace:true` and `confirm:true`.

## TLS and backups

`tls_get_status` reports the active leaf certificate's issuer, subject, serial,
expiry, SANs, vhost/CloudPanel-record consistency, and an expiry-based
`renewal_health`. It deliberately does not claim that a renewal job succeeded,
because CloudPanel has no reliable renewal-history primitive.

Backups are encrypted local recovery objects, not network downloads. They can
contain files, CloudPanel-related databases, or both. They expire after seven
days and share a 10 GiB retention quota. Restore always creates a matching
pre-restore safety backup first, then requires explicit confirmation and the
local `backup.restore` policy.
