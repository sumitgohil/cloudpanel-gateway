# Installation

CloudPanel Gateway supports Ubuntu 24.04 hosts with CloudPanel and `clpctl`
already installed. Installation must be run as root on the CloudPanel server.

## What the installer does

The production installer downloads the architecture-specific release binary,
verifies `SHA256SUMS` and Minisign signatures using the repository public key,
then creates the system account, state directories, configuration, and three
systemd services:

- `cloudpanel-gateway.service` — unprivileged API, OpenAPI, metrics, and MCP.
- `cloudpanel-gateway-helper.service` — root-only typed CloudPanel helper.
- `cloudpanel-gateway-nginx-commit.service` — root-only, isolated Nginx
  validation and commit service.

It writes a one-time bootstrap token to
`/root/cloudpanel-gateway-bootstrap-token.txt` with mode `0600`.

The installer validates root access, Ubuntu version, `clpctl`, and supported
CPU architecture before changing service state. It does not install a public
reverse proxy or request a certificate automatically; those are explicit local
administrator actions after installation.

## Production install

Use a checked-out release so the install script has the matching systemd unit
files. Replace the release below with the version you want to install.

```bash
sudo apt-get update
sudo apt-get install --yes git
git clone https://github.com/sumitgohil/cloudpanel-gateway.git
cd cloudpanel-gateway
git checkout v0.1.0
sudo ./install.sh --version 0.1.0
```

The embedded public key is used by default. To use an approved replacement key
for a private fork, pass `--public-key` or set `CPG_MINISIGN_PUBLIC_KEY` for
the installer process.

## First access

Read the bootstrap token once, store it in a password manager or secret store,
then remove the file:

```bash
sudo cat /root/cloudpanel-gateway-bootstrap-token.txt
sudo rm /root/cloudpanel-gateway-bootstrap-token.txt
```

Create scoped replacement tokens promptly and revoke the bootstrap token if it
will no longer be used:

```bash
sudo cloudpanel-gateway token create --label operations --scopes 'admin,docs:read,metrics:read'
sudo cloudpanel-gateway token list
sudo cloudpanel-gateway token revoke --id tok_example
```

`admin` satisfies scope checks, but it does **not** bypass server policy for
dangerous operations. Those operations must be enabled locally as well.

## Publish the gateway safely

The service binds to `127.0.0.1:9780` by default. Publish it only through a
CloudPanel reverse-proxy site after DNS resolves to the server:

```bash
sudo cloudpanel-gateway domain map \
  --domain panel.example.com \
  --expected-ip 203.0.113.10

sudo cloudpanel-gateway domain tls issue --domain panel.example.com
```

The domain mapper creates a dedicated managed CloudPanel site user and saves
its generated credential in root-controlled gateway state. `domain tls issue`
does not run until a proxy mapping exists.

## Verify the installation

```bash
sudo cloudpanel-gateway doctor
sudo systemctl status cloudpanel-gateway cloudpanel-gateway-helper cloudpanel-gateway-nginx-commit
curl --fail http://127.0.0.1:9780/healthz
```

For authenticated checks, use a scoped token. `/openapi.json` and `/docs`
require `docs:read`; `/metrics` requires `metrics:read`.

## Upgrade and rollback

Back up `/etc/cloudpanel-gateway` and `/var/lib/cloudpanel-gateway` before an
upgrade. Check out a newer signed release and run the installer again. The
state database, token pepper, and existing configuration are retained.

To roll back, check out the previous release and rerun its installer. Confirm
the target version is compatible with the persisted state before changing a
production host.

## Development-only installation

`--local-binary` is intended for a disposable test VM. It bypasses release
download/signature checks and must not be used for production deployment:

```bash
sudo ./install.sh --local-binary ./cloudpanel-gateway
```
