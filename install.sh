#!/usr/bin/env bash
set -euo pipefail

RELEASE_VERSION=""
RELEASE_BASE="https://github.com/sumitgohil/cloudpanel-gateway/releases/download"
DEFAULT_PUBLIC_KEY="RWSc0fp65r6GcJiRAcydy1W60Jk8kvusaJyijgESv0WLwPaEd15sohP/"
PUBLIC_KEY="${CPG_MINISIGN_PUBLIC_KEY:-$DEFAULT_PUBLIC_KEY}"
LOCAL_BINARY=""

usage() {
  cat <<'EOF'
Usage: sudo ./install.sh [options]

Installs CloudPanel Gateway on Ubuntu with CloudPanel already installed.

  --version VERSION       Signed release version (required unless --local-binary)
  --release-base URL      Release download base URL
  --public-key KEY        override the embedded Minisign public key
  --local-binary PATH     Development-only prebuilt Linux binary
  --help                  Show this help

Production installs verify both signed SHA256SUMS and Minisign release assets.
--local-binary is for a controlled test VM only and never bypasses binary
permission or OS checks.
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) RELEASE_VERSION="$2"; shift 2;;
    --release-base) RELEASE_BASE="$2"; shift 2;;
    --public-key) PUBLIC_KEY="$2"; shift 2;;
    --local-binary) LOCAL_BINARY="$2"; shift 2;;
    --help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
command -v clpctl >/dev/null || { echo "CloudPanel clpctl is required." >&2; exit 1; }
source /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] || { echo "Ubuntu 24.04 is required." >&2; exit 1; }
ARCH="$(uname -m)"
case "$ARCH" in x86_64) ARCH=amd64;; aarch64) ARCH=arm64;; *) echo "Unsupported architecture." >&2; exit 1;; esac

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
binary="$tmp_dir/cloudpanel-gateway"
if [[ -n "$LOCAL_BINARY" ]]; then
  [[ -f "$LOCAL_BINARY" && -x "$LOCAL_BINARY" ]] || { echo "Invalid local binary." >&2; exit 1; }
  cp "$LOCAL_BINARY" "$binary"
else
  [[ -n "$RELEASE_VERSION" && -n "$PUBLIC_KEY" ]] || { echo "--version is required for signed release installs." >&2; exit 2; }
  [[ "$RELEASE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]] || { echo "--version must be semantic without a v prefix." >&2; exit 2; }
  command -v curl >/dev/null || { apt-get update; apt-get install --yes --no-install-recommends curl; }
  command -v minisign >/dev/null || { apt-get update; apt-get install --yes --no-install-recommends minisign; }
  command -v sha256sum >/dev/null || { echo "sha256sum is required to verify releases." >&2; exit 1; }
  asset="cloudpanel-gateway_${RELEASE_VERSION}_linux_${ARCH}"
  base="${RELEASE_BASE}/v${RELEASE_VERSION}"
  binary="$tmp_dir/$asset"
  curl --fail --location --proto '=https' --tlsv1.2 -o "$binary" "$base/$asset"
  curl --fail --location --proto '=https' --tlsv1.2 -o "$binary.minisig" "$base/$asset.minisig"
  curl --fail --location --proto '=https' --tlsv1.2 -o "$tmp_dir/SHA256SUMS" "$base/SHA256SUMS"
  curl --fail --location --proto '=https' --tlsv1.2 -o "$tmp_dir/SHA256SUMS.minisig" "$base/SHA256SUMS.minisig"
  minisign -Vm "$tmp_dir/SHA256SUMS" -P "$PUBLIC_KEY"
  expected_sha="$(awk -v name="$asset" '$2 == name { print $1; found=1 } END { if (!found) exit 1 }' "$tmp_dir/SHA256SUMS")" || { echo "release checksum entry is missing." >&2; exit 1; }
  printf '%s  %s\n' "$expected_sha" "$binary" | sha256sum --check --status - || { echo "release checksum verification failed." >&2; exit 1; }
  minisign -Vm "$binary" -P "$PUBLIC_KEY"
fi

install -d -m 0755 /etc/cloudpanel-gateway
install -d -m 0750 /var/lib/cloudpanel-gateway/artifacts /run/cloudpanel-gateway
if ! id -u cloudpanel-gateway >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/cloudpanel-gateway --shell /usr/sbin/nologin cloudpanel-gateway
fi
gateway_gid="$(id -g cloudpanel-gateway)"
chown cloudpanel-gateway:cloudpanel-gateway /var/lib/cloudpanel-gateway /var/lib/cloudpanel-gateway/artifacts
install -m 0755 "$binary" /usr/local/bin/cloudpanel-gateway
if [[ ! -f /etc/cloudpanel-gateway/config.json ]]; then
  cat > /etc/cloudpanel-gateway/config.json <<EOF
{"listen":"127.0.0.1:9780","helper_socket":"/run/cloudpanel-gateway/helper.sock","helper_gid":${gateway_gid},"database":"/var/lib/cloudpanel-gateway/state.db","artifact_dir":"/var/lib/cloudpanel-gateway/artifacts","secret_file":"/var/lib/cloudpanel-gateway/token-pepper","allowed_hosts":[]}
EOF
  # The config contains no credential material; the token pepper is a separate
  # root:gateway-readable file. The unprivileged service must read this file.
  chmod 0644 /etc/cloudpanel-gateway/config.json
fi
install -m 0644 "$(dirname "$0")/deploy/systemd/cloudpanel-gateway-helper.service" /etc/systemd/system/cloudpanel-gateway-helper.service
install -m 0644 "$(dirname "$0")/deploy/systemd/cloudpanel-gateway-nginx-commit.service" /etc/systemd/system/cloudpanel-gateway-nginx-commit.service
install -m 0644 "$(dirname "$0")/deploy/systemd/cloudpanel-gateway.service" /etc/systemd/system/cloudpanel-gateway.service
if [[ ! -f /var/lib/cloudpanel-gateway/state.db ]]; then
  /usr/local/bin/cloudpanel-gateway --config /etc/cloudpanel-gateway/config.json bootstrap
fi
chown cloudpanel-gateway:cloudpanel-gateway /var/lib/cloudpanel-gateway/state.db
chown root:cloudpanel-gateway /var/lib/cloudpanel-gateway/token-pepper
chmod 0640 /var/lib/cloudpanel-gateway/token-pepper
systemctl daemon-reload
systemctl enable --now cloudpanel-gateway-nginx-commit.service cloudpanel-gateway-helper.service cloudpanel-gateway.service
curl --fail --silent --show-error http://127.0.0.1:9780/readyz >/dev/null
echo "Installed CloudPanel Gateway. Read the one-time bootstrap token in /root/cloudpanel-gateway-bootstrap-token.txt."
