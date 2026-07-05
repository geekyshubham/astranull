#!/bin/bash
# GCP lab: bare origin (no WAF) — intentional misconfiguration for DO-hosted platform tests.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends nginx curl ca-certificates git rsync
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y nodejs
mkdir -p /opt/astranull/agent /var/lib/astranull /etc/astranull
chmod 700 /var/lib/astranull
cat >/etc/nginx/sites-available/default <<'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    # Marker probes carry x-astranull-nonce; forward to local canary for placement correlation.
    location / {
        if ($http_x_astranull_nonce != "") {
            proxy_pass http://127.0.0.1:18080;
            break;
        }
        return 200 "origin_ok_no_waf";
        add_header Content-Type text/plain;
    }
}
NGINX
nginx -t
systemctl enable nginx
systemctl restart nginx
cat >/etc/systemd/system/astranull-agent.service <<'UNIT'
[Unit]
Description=AstraNull agent → DigitalOcean control plane
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=-/etc/astranull/agent.env
ExecStart=/usr/bin/node /opt/astranull/agent/astranull-agent.mjs --canary-listen 18080 --daemon-interval 30000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
echo "astranull-gcp-bare-ready" >/var/log/astranull-gcp-bare-ready