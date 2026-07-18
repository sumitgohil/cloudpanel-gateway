# Releases and verification

Releases are created only by the **Release** GitHub Actions workflow when it is
manually dispatched from `main`. The workflow requires a semantic version
without a leading `v`, for example `0.2.0`; it creates the matching `v0.2.0`
tag and GitHub Release.

Each release contains Linux `amd64` and `arm64` binaries, a `SHA256SUMS`
manifest, Minisign signatures for every binary and the manifest, and GitHub
build provenance attestations.

## Maintainer setup

The repository needs the following Actions configuration:

- secret `MINISIGN_SECRET_KEY`: base64-encoded Minisign secret key converted
  for no-password CI signing with `-W`;
- variable `CPG_MINISIGN_PUBLIC_KEY`: public verification key; and
- Actions workflow permissions set to **Read and write**.

The private key never enters the repository or a release asset. The public key
is deliberately committed in `cloudpanel-gateway.minisign.pub` and embedded in
the installer.

Minisign has no non-interactive signing passphrase flag. Convert the dedicated
CI signing key once (preserving its public key), then replace the Actions
secret with its base64-encoded result:

```bash
cp cloudpanel-gateway.minisign.key cloudpanel-gateway.minisign.key.backup
minisign -C -s cloudpanel-gateway.minisign.key -W
base64 < cloudpanel-gateway.minisign.key | tr -d '\n' | pbcopy
```

Confirm before uploading that decoding the clipboard value prints
`untrusted comment: minisign encrypted secret key`. Despite that header,
`-W` creates a key usable without an interactive password prompt. Do not configure
`MINISIGN_PASSWORD`; a password-protected key fails closed rather than prompting
in CI.

## Manual verification

```bash
minisign -Vm cloudpanel-gateway_0.2.0_linux_amd64 -P "$(sed -n '2p' cloudpanel-gateway.minisign.pub)"
minisign -Vm SHA256SUMS -P "$(sed -n '2p' cloudpanel-gateway.minisign.pub)"
sha256sum --check SHA256SUMS
```

The installer performs equivalent verification before it places a release
binary in `/usr/local/bin`.
