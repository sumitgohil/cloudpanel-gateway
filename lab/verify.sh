#!/usr/bin/env bash
set -Eeuo pipefail

readonly access_file=/root/cloudpanel-gateway-test-lab/access.json

json_value() {
  local key="$1"
  sed -n "s/.*\"${key}\":\"\([^\"]*\)\".*/\1/p" "$access_file"
}

for service in cloudpanel-gateway-nginx-commit.service cloudpanel-gateway-helper.service cloudpanel-gateway.service; do
  systemctl is-active --quiet "$service" || { echo "service is not active: $service" >&2; exit 1; }
done

cloudpanel-gateway doctor >/dev/null
curl --fail --silent http://127.0.0.1:9780/readyz | grep -q '"status":"ready"'
clpctl user:list | grep -Fq lab-admin

domain="$(json_value gateway_domain)"
ip="$(json_value vm_ip)"
token="$(json_value gateway_token)"
[[ -n "$domain" && -n "$ip" && -n "$token" ]] || { echo "invalid lab access file" >&2; exit 1; }
getent hosts "$domain" | grep -Fq "$ip"
curl --fail --silent --resolve "${domain}:80:${ip}" "http://${domain}/healthz" | grep -q '"status"'
curl --fail --silent -H "Authorization: Bearer ${token}" http://127.0.0.1:9780/openapi.json >/dev/null

policy_json="$(cloudpanel-gateway policy list)"
if grep -q ':true' <<<"$policy_json"; then
  echo "dangerous lab policies must remain disabled" >&2
  exit 1
fi
[[ "$(stat -c '%a' "$access_file")" == 600 ]] || { echo "access file must be mode 0600" >&2; exit 1; }
echo "CloudPanel Gateway test lab verification passed."
