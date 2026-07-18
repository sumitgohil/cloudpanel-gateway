# Security model

CloudPanel Gateway is a privileged integration. Treat its bearer tokens as
production credentials and deploy it behind TLS on a trusted hostname.

## Privilege separation

- The API/MCP service runs as `cloudpanel-gateway`, has no login shell, and is
  loopback-only by default.
- The root helper receives only a versioned typed Unix-socket protocol. It
  independently validates an action allowlist and invokes `clpctl` through
  `exec.CommandContext` argument arrays.
- The Nginx commit service is separate from the helper and accepts only
  validated generated vhost content. It tests Nginx and rolls back failed
  updates.
- No REST endpoint or MCP tool executes a user-provided shell command.

`NoNewPrivileges=true` prevents the public service and helper from gaining
additional privileges through setuid/setgid programs or file capabilities.
`MemoryDenyWriteExecute=true` is retained everywhere except the separate
Nginx commit service, where CloudPanel's PageSpeed module requires executable
stack support while `nginx -t` loads it.

## Tokens, logs, and auditing

Tokens are high-entropy opaque values. Only a keyed digest is stored. Audit
records retain token ID, action, outcome, request ID, and duration, but redact
credentials, authorization headers, cookies, certificates, and log secrets.

Use individual, short-lived least-privilege tokens. Revoke a token immediately
after suspected exposure:

```bash
sudo cloudpanel-gateway token revoke --id tok_example
```

Log readers receive redacted values. An `admin` token may request raw log lines
only when this is necessary for an incident; do not paste raw logs into public
issues.

## Operational guidance

- Keep `/root/cloudpanel-gateway-bootstrap-token.txt` only long enough to
  transfer the bootstrap token to a secret manager.
- Do not commit `.env` files, token files, Minisign private keys, or database
  exports. The repository `.gitignore` rejects common key file patterns.
- Enable dangerous policy operations only temporarily and disable them again
  after use.
- Review the specific scopes granted to an AI client. It should not receive
  `admin` unless there is a compelling operational requirement.
- Back up gateway state before upgrades and test changes on a disposable VM.

To report a vulnerability privately, follow [SECURITY.md](../SECURITY.md).
