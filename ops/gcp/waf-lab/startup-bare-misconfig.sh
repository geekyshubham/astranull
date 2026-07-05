#!/bin/bash
# GCP lab: "WAF present but broken" — fingerprints look protected but markers leak to origin.
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

    # Misconfiguration: marker NOT blocked — passes through to origin (200).
    location / {
        return 200 "waf_marker_leaked_to_origin";
        add_header Content-Type text/plain;
    }
}
NGINX
nginx -t
systemctl enable nginx
systemctl restart nginx
echo "astranull-gcp-waf-misconfig-ready" >/var/log/astranull-gcp-waf-misconfig-ready