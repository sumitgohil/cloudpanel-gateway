#!/usr/bin/env bash
set -Eeuo pipefail

readonly versions_file=/tmp/cloudpanel-gateway-lab-versions.env
readonly source_archive=/tmp/cloudpanel-gateway-source.tar
readonly state_dir=/var/lib/cloudpanel-gateway-test-lab
readonly access_file=/root/cloudpanel-gateway-test-lab/access.json
readonly source_dir=/opt/cloudpanel-gateway-test-lab/source
readonly binary_path=/opt/cloudpanel-gateway-test-lab/cloudpanel-gateway

[[ -r "$versions_file" ]] || { echo "missing lab version pins" >&2; exit 1; }
[[ -r "$source_archive" ]] || { echo "missing gateway source archive" >&2; exit 1; }
# shellcheck disable=SC1090
source "$versions_file"

require_ubuntu_2404() {
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]] || {
    echo "the test lab requires Ubuntu 24.04" >&2
    exit 1
  }
}

wait_for() {
  local description="$1"
  shift
  local _
  for _ in {1..90}; do
    if "$@"; then
      return 0
    fi
    sleep 2
  done
  echo "timed out waiting for ${description}" >&2
  return 1
}

random_hex() {
  openssl rand -hex "$1"
}

install_cloudpanel() {
  if command -v clpctl >/dev/null 2>&1; then
    return 0
  fi

  local installer=/tmp/cloudpanel-install.sh
  curl --fail --location --proto '=https' --tlsv1.2 -o "$installer" "$CLOUDPANEL_INSTALL_URL"
  printf '%s  %s\n' "$CLOUDPANEL_INSTALL_SHA256" "$installer" | sha256sum --check --status -
  DEBIAN_FRONTEND=noninteractive DB_ENGINE="$CLOUDPANEL_DB_ENGINE" bash "$installer"
}

install_go() {
  local machine arch checksum archive
  machine="$(uname -m)"
  case "$machine" in
    x86_64) arch=amd64; checksum="$GO_SHA256_AMD64" ;;
    aarch64|arm64) arch=arm64; checksum="$GO_SHA256_ARM64" ;;
    *) echo "unsupported guest architecture: ${machine}" >&2; exit 1 ;;
  esac
  archive="/tmp/go${GO_VERSION}.linux-${arch}.tar.gz"
  curl --fail --location --proto '=https' --tlsv1.2 -o "$archive" "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"
  printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --status -
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$archive"
}

create_cloudpanel_admin() {
  local marker="$state_dir/cloudpanel-admin-password"
  if [[ -s "$marker" ]]; then
    return 0
  fi
  local password
  password="$(random_hex 24)"
  clpctl user:add \
    --userName=lab-admin \
    --email=lab-admin@cpgw.test \
    --firstName=Lab \
    --lastName=Administrator \
    --password="$password" \
    --role=admin \
    --timezone=UTC \
    --status=1
  umask 077
  printf '%s\n' "$password" > "$marker"
}

build_and_install_gateway() {
  rm -rf "$source_dir"
  install -d -m 0755 "$source_dir"
  tar -C "$source_dir" -xf "$source_archive"
  [[ -f "$source_dir/install.sh" && -f "$source_dir/go.mod" ]] || {
    echo "source archive is not a CloudPanel Gateway checkout" >&2
    exit 1
  }
  PATH=/usr/local/go/bin:$PATH CGO_ENABLED=0 go build -trimpath -o "$binary_path" "$source_dir/cmd/cloudpanel-gateway"
  chmod 0755 "$binary_path"
  "$source_dir/install.sh" --local-binary "$binary_path"
}

configure_gateway_domain() {
  if ! grep -qE "^[[:space:]]*${LAB_IP//./\\.}[[:space:]]+.*\\b${LAB_DOMAIN//./\\.}\\b" /etc/hosts; then
    printf '%s\t%s\n' "$LAB_IP" "$LAB_DOMAIN" >> /etc/hosts
  fi
  if ! cloudpanel-gateway domain status --domain "$LAB_DOMAIN" >/dev/null 2>&1; then
    cloudpanel-gateway domain map --domain "$LAB_DOMAIN"
  fi
}

write_access_file() {
  local token password
  token="$(tr -d '\r\n' < /root/cloudpanel-gateway-bootstrap-token.txt)"
  password="$(tr -d '\r\n' < "$state_dir/cloudpanel-admin-password")"
  [[ -n "$token" && -n "$password" ]] || { echo "missing generated lab credentials" >&2; exit 1; }
  install -d -m 0700 "$(dirname "$access_file")"
  umask 077
  cat > "$access_file" <<EOF
{"vm_ip":"${LAB_IP}","cloudpanel_url":"https://${LAB_IP}:8443","cloudpanel_username":"lab-admin","cloudpanel_password":"${password}","gateway_domain":"${LAB_DOMAIN}","gateway_url":"http://${LAB_DOMAIN}","mcp_url":"http://${LAB_DOMAIN}/mcp","gateway_token":"${token}","hosts_entry":"${LAB_IP} ${LAB_DOMAIN}"}
EOF
  chmod 0600 "$access_file"
}

main() {
  require_ubuntu_2404
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install --yes --no-install-recommends ca-certificates curl openssl sudo tar wget xz-utils
  install -d -m 0700 "$state_dir"

  install_cloudpanel
  wait_for "CloudPanel CLI" command -v clpctl
  wait_for "Nginx" systemctl is-active --quiet nginx
  wait_for "CloudPanel UI" curl --fail --silent --insecure https://127.0.0.1:8443/
  create_cloudpanel_admin

  install_go
  build_and_install_gateway
  configure_gateway_domain
  write_access_file

  install -d -m 0700 /usr/local/lib/cloudpanel-gateway-test-lab
  install -m 0700 /tmp/cloudpanel-gateway-lab-verify.sh /usr/local/lib/cloudpanel-gateway-test-lab/verify.sh
  /usr/local/lib/cloudpanel-gateway-test-lab/verify.sh
}

main "$@"
