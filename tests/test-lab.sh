#!/usr/bin/env bash
set -Eeuo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash -n "$root_dir/scripts/test-lab"
bash -n "$root_dir/lab/provision.sh"
bash -n "$root_dir/lab/verify.sh"

# shellcheck disable=SC1091
source "$root_dir/lab/versions.env"
[[ "$LAB_IP" =~ ^192\.168\.56\.[0-9]{1,3}$ ]]
[[ "$LAB_DOMAIN" == gateway.cpgw.test ]]
[[ "$VAGRANT_BOX" == bento/ubuntu-24.04 ]]
[[ "$VAGRANT_BOX_VERSION" =~ ^[0-9]{6}\.[0-9]{2}\.[0-9]+$ ]]
[[ "$CLOUDPANEL_INSTALL_SHA256" =~ ^[a-f0-9]{64}$ ]]
[[ "$GO_SHA256_AMD64" =~ ^[a-f0-9]{64}$ ]]
[[ "$GO_SHA256_ARM64" =~ ^[a-f0-9]{64}$ ]]

grep -Fq "git -C \"\$root_dir\" archive" "$root_dir/scripts/test-lab"
grep -Fq 'disabled: true' "$root_dir/Vagrantfile"
grep -Fq 'dangerous lab policies must remain disabled' "$root_dir/lab/verify.sh"
echo "test-lab static checks passed"
