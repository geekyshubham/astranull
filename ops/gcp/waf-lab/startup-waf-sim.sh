#!/bin/bash
# GCP lab: WAF/CDN simulation — Cloudflare-like fingerprints, blocks AstraNull markers.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends nginx
cat >/etc/nginx/sites-available/default <<'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    add_header cf-ray "$request_id" always;
    add_header cf-cache-status "DYNAMIC" always;
    add_header Server "cloudflare" always;

    if ($http_x_astranull_marker) { return 444; }
    if ($http_x_astranull_nonce) { return 444; }

    location / {
        return 403 "blocked_by_edge_waf";
    }
}
NGINX
nginx -t
systemctl enable nginx
systemctl restart nginx
echo "astranull-gcp-waf-sim-ready" >/var/log/astranull-gcp-waf-sim-ready