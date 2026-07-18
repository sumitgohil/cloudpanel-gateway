# CloudPanel Gateway

CloudPanel Gateway is a Go API, MCP, and local administration CLI for the CloudPanel `clpctl` CLI. It never runs a shell command: every operation is a typed, validated action executed by a root-only local helper.

## Local development

```bash
go test ./...
go build -o cloudpanel-gateway ./cmd/cloudpanel-gateway
./cloudpanel-gateway --config ./dev-config.json bootstrap --bootstrap-token-file ./bootstrap-token.txt
```

`serve` and `helper` are separate service modes. The gateway serves REST at `/v1`, OpenAPI at `/openapi.json`, docs at `/docs`, metrics at `/metrics`, and MCP Streamable HTTP at `/mcp`.

## Production installation

Use a signed release:

```bash
sudo CPG_MINISIGN_PUBLIC_KEY='...' ./install.sh --version 0.1.0
```

For the disposable VM only, a prebuilt binary may be passed with `--local-binary`. The installer creates two systemd units and writes the initial token once to `/root/cloudpanel-gateway-bootstrap-token.txt`.

Then create the CloudPanel reverse proxy and explicitly issue TLS:

```bash
sudo cloudpanel-gateway domain map --domain panel1.psng.tech --expected-ip 212.2.252.221
sudo cloudpanel-gateway domain tls issue --domain panel1.psng.tech
```

Run `cloudpanel-gateway --help` and `cloudpanel-gateway <command> --help` for all local administrative commands. Dangerous actions remain disabled until `policy enable --operation <name>` is run locally.
