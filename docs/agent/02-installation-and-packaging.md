# Agent Installation and Packaging

## Installation goals

AstraNull must be easy to install across enterprise environments.

Supported install methods:

| Method | Use case |
|---|---|
| One-line Linux installer | Fast onboarding on VMs/bare metal. |
| deb package | Ubuntu/Debian. |
| rpm package | RHEL/Rocky/Alma/CentOS/Amazon Linux/SUSE-family where applicable. |
| Static tarball | Unknown Linux distros or locked-down environments. |
| Docker image | Canary container or simple containerized deployment. |
| Helm chart | Kubernetes: GKE/EKS/AKS/OpenShift. |
| Cloud startup script | AWS/GCP/Azure VM bootstrap. |
| MSI/Windows service | Future roadmap if customers need Windows servers. |

## Hosted packages

AstraNull main service should host:

```text
https://download.astranull.example/install.sh
https://download.astranull.example/agent/linux/amd64/astranull-agent.tar.gz
https://download.astranull.example/apt/...
https://download.astranull.example/yum/...
https://charts.astranull.example/
```

Every package must be signed. The installer must verify signatures/checksums before installing.

## Current implementation status (repository)

| Capability | Status |
|---|---|
| Generic Linux install (`agents/linux/install.sh`) | Ships: SHA-256 artifact verification, systemd unit, private bootstrap token file, non-secret `agent.env`. |
| Generic Linux uninstall (`agents/linux/uninstall.sh`) | Ships: bounded removal of binary, `agent.env`, systemd unit; optional `--purge-data` for `/var/lib/astranull`; production `systemctl` stop/disable when root is `/`. |
| Signed generic Linux tarball builder (`scripts/package-agent.mjs`) | Ships: staged package directory, `.tar.gz`, manifest (per-file and artifact SHA-256/size), optional Ed25519 manifest signature (`.manifest.json.sig`). Control-plane release API re-verifies the same manifest contract on create/rollback; agent supports `--verify-update-manifest` preflight, `--apply-update-manifest` host apply, and `--download-and-apply-update` (HTTPS-only download by default; `--allow-insecure-localhost-downloads` for test-only localhost HTTP; rejects URL credentials; size/timeout caps; no redirect follow) — writes `releases/<version>/` and `current.json` under `--install-root`. |
| Native `.deb` / `.rpm` builders (`scripts/package-agent.mjs --format deb,rpm`) | Ships: pure Node Debian binary package (`debian-binary`, `control.tar.gz`, `data.tar.gz`); RPM via `rpmbuild` when on PATH, or `--rpm-spec-only` for spec/BUILDROOT without `rpmbuild`. Unit tests in `tests/unit/agent-package.test.mjs`. **Not shipped for production:** apt/yum repo publishing, GPG/package signing, distro matrix validation, hosted artifact custody. |
| GPG / cosign image signing | Not implemented for packages or container images — tarball path uses Ed25519 manifest signing when a release key is configured; install still relies on `--sha256` until customer-facing verification is wired. |
| Hosted `download.astranull.example` | Not wired — use local path or customer-hosted tarball in validation. |
| Docker image | Non-root Alpine image in `agents/linux/Dockerfile` (single `astranull-agent.mjs`, `.dockerignore`, OCI labels, no baked bootstrap token); `pnpm run agent:container:evidence` records local build/verify evidence; registry publish and image signing pending. |
| Agent package SBOM/provenance evidence (`scripts/agent-sbom-provenance-evidence.mjs`) | Ships: metadata-only manifest from package artifact plus CycloneDX/SPDX SBOM and in-toto/SLSA-style provenance JSON (SHA-256/size digests, format label, redacted summaries). Rejects missing/empty inputs, unsafe package names, and secret-bearing evidence. Does not execute packages, install artifacts, call registries, or require Docker. **Not a substitute for** GPG/cosign signing, apt/yum publishing, or distro/Kubernetes install-matrix validation — promotion still needs hosted custody and staging signoff. |
| Helm chart | `mode: daemonset` (default) or `deployment`; bootstrap token mounted as file via Secret (`bootstrapToken` value creates Secret, or pre-created `bootstrapTokenSecretName`); durable `/var/lib/astranull` identity storage defaults to hostPath with PVC/emptyDir options; `tests/unit/agent-helm.test.mjs` validates templates. |

Bootstrap tokens are never echoed by the installer. Production installs store the one-time token at `/var/lib/astranull/bootstrap-token` (mode `0600`). The agent deletes that file after successful registration.

## Signed generic tarball builder (repository)

Use this path to produce a checksum manifest and optional signature before hosting or handing artifacts to customers. The builder does not publish artifacts or embed bootstrap tokens.

Local build (default output `dist/agent/`):

```bash
pnpm run agent:package
# or
node scripts/package-agent.mjs --output-dir ./dist/agent --version 0.2.0-production-readiness
```

With release signing (Ed25519 PKCS#8 private key, DER, base64):

```bash
export ASTRANULL_AGENT_SIGNING_PRIVATE_KEY="<base64_der_pkcs8_ed25519_private_key>"
pnpm run agent:package
```

Outputs (example version `0.2.0-production-readiness`):

| Artifact | Purpose |
|---|---|
| `astranull-agent-<version>/` | Staged directory: `astranull-agent.mjs`, `install.sh`, `uninstall.sh`, `systemd/astranull-agent.service`. |
| `astranull-agent-<version>.tar.gz` | Generic Linux fallback package. |
| `astranull-agent-<version>.manifest.json` | Package name/version, `created_at`, per-file `sha256`/`size`, artifact `sha256`/`size`, signing metadata (`algorithm`, `public_key_der_base64` when signed). |
| `astranull-agent-<version>.manifest.json.sig` | Base64 Ed25519 signature over canonical JSON of manifest fields excluding signature material (stable key-sorted JSON). |

Install flow for tarball customers: verify manifest signature (agent CLI `--verify-update-manifest` or equivalent), confirm tarball `sha256` matches manifest, then run `install.sh` with `--sha256` and `--agent-source` or `--agent-url` as today.

### SBOM and provenance evidence (repository)

Capture promotion metadata for generic tarballs, `.deb`, `.rpm`, or container artifacts without running installers or cloud tooling:

```bash
node scripts/agent-sbom-provenance-evidence.mjs \
  --package ./dist/agent/astranull-agent-0.2.0.tar.gz \
  --sbom ./evidence/agent.cyclonedx.json \
  --provenance ./evidence/agent.provenance.json \
  --format tar \
  --out ./output/agent-sbom-provenance-evidence.json
```

The utility validates that the SBOM includes a CycloneDX or SPDX marker, that provenance includes `subject`, `materials`, and predicate metadata, and writes a redacted evidence manifest (digests and summaries only). It is **evidence capture for release review**, not a replacement for package/image signing, customer mirror custody, or install/uninstall drills across supported distros and Kubernetes modes. In-place upgrades can use `--apply-update-manifest` or `--download-and-apply-update` on the host (path/symlink hardened, download policy as above), including URLs from poll `download` on `GET /v1/agents/:id/update`. Release admins supply absolute HTTPS `distribution` URLs when creating releases (`POST /v1/agent-updates`). Unattended fleet rollout still requires update-daemon wiring, hosted artifact custody/CDN ops evidence, and service restart orchestration.

## Native package builder (repository)

Build distro-native artifacts locally or in CI (default output under `dist/agent/`):

```bash
pnpm run agent:package:native
# tarball + deb + rpm in one pass:
pnpm run agent:package:all
# or explicitly:
node scripts/package-agent.mjs --format deb,rpm --rpm-spec-only
```

| Command / flag | Behavior |
|---|---|
| `--format deb` | Emits a `.deb` with `debian-binary`, `control.tar.gz`, and `data.tar.gz`. |
| `--format rpm` | Runs `rpmbuild` when available and fails if no RPM artifact is produced. |
| `--rpm-spec-only` | Stages RPM spec and BUILDROOT without invoking `rpmbuild` (builder/CI hosts without RPM tooling). |

**Installed paths** (deb and rpm):

| Path | Purpose |
|---|---|
| `/usr/local/bin/astranull-agent.mjs` | Agent binary. |
| `/etc/systemd/system/astranull-agent.service` | Systemd unit (not enabled/started by package scripts). |
| `/etc/astranull/agent.env.example` | Non-secret example only — operators copy to `/etc/astranull/agent.env`. |
| `/var/lib/astranull/` | State directory placeholder. |

**Safety guarantees:** packages do not include bootstrap tokens, live `/etc/astranull/agent.env`, tenant credentials, or other secrets. `postinst` reloads systemd but does not enable or start the service until the operator configures `agent.env` and enrollment. `prerm` stops `astranull-agent.service` before package removal.

### Remaining packaging blockers

| Area | Status |
|---|---|
| apt/yum repository publishing | Not implemented — native `.deb`/`.rpm` artifacts can be built locally; hosted apt/yum indexes and customer mirror runbooks remain. |
| Distro matrix validation | Not evidenced — Ubuntu/Debian, RHEL family, Amazon Linux, and SUSE targets need install/uninstall drills on real distros. |
| GPG-signed `.deb`/`.rpm` | Not implemented — separate from Ed25519 manifest signing on generic tarballs. |
| cosign / registry signing for `agents/linux/Dockerfile` image | Not implemented. |
| Hosted artifact custody and host trust enforcement | Control-plane `distribution` metadata on releases and poll `download` payloads are implemented in developer validation; operators publish manifests/signatures/tarballs (and eventually signed native packages) to customer CDN or mirror and register HTTPS URLs on release create. Host `--apply-update-manifest` and `--download-and-apply-update` consume those URLs when invoked. **Remaining:** CDN/mirror custody runbooks and staging evidence, production trust-key ceremony/custody/rotation/revocation drill, installer/update-daemon enforcement of pinned tenant trust keys on generic, deb/rpm, and container paths, unattended daemon restart, and distro/Kubernetes fleet rollout + rollback drills (`AG-014`). |

## One-line Linux install flow

```text
User copies command from UI
  -> install.sh detects OS/distro/arch/init system
  -> verifies token format locally
  -> chooses deb/rpm/tarball path
  -> downloads signed package
  -> verifies checksum/signature
  -> writes /etc/astranull/agent.yaml
  -> creates astranull user/group
  -> installs systemd service
  -> starts service
  -> agent registers outbound
  -> UI shows agent online
```

## Example install command (generic path)

```bash
# After publishing a checksum manifest for the agent artifact:
curl -fsSL https://download.astranull.example/install.sh | sudo bash -s -- \
  --token <BOOTSTRAP_TOKEN> \
  --agent-url https://download.astranull.example/agent/linux/amd64/astranull-agent.mjs \
  --sha256 <64_HEX_SHA256> \
  --api https://api.astranull.example \
  --agent-name prod-origin-01
```

Local/staged validation (no root):

```bash
SHA=$(shasum -a 256 agents/linux/astranull-agent.mjs | awk '{print $1}')
agents/linux/install.sh \
  --token <BOOTSTRAP_TOKEN> \
  --sha256 "$SHA" \
  --agent-source agents/linux/astranull-agent.mjs \
  --install-root /tmp/astranull-staged \
  --no-start \
  --api http://127.0.0.1:3000 \
  --allow-insecure-localhost-api
```

## Supported Linux distributions

| Family | Package path | Notes |
|---|---|---|
| Ubuntu/Debian | deb | systemd service. |
| RHEL/Rocky/Alma/CentOS | rpm | systemd service. |
| Amazon Linux | rpm | EC2 common path. |
| SUSE/openSUSE | rpm or tarball | Validate packaging separately. |
| Generic Linux | tarball | Static binary fallback. |

## Install options

| Option | Description |
|---|---|
| `--token` | Bootstrap token. Required. |
| `--agent-name` | Friendly name. Optional. |
| `--env` | Environment. Optional if token pre-binds. |
| `--target-group` | Optional binding. |
| `--mode` | Observation modes. |
| `--proxy` | Enterprise outbound proxy. |
| `--no-start` | Install but do not start service. |
| `--config` | Use custom config file. |
| `--dry-run` | Validate environment without installing. |
| `--sha256` | Required for non-dry-run; verifies agent artifact before install. |
| `--agent-source` / `--agent-url` | Local path or HTTPS download for agent artifact. |
| `--install-root` | Staged install root for tests (default `/`). |

## Uninstall options (generic Linux script)

| Option | Description |
|---|---|
| `--dry-run` | Show planned removals; no files deleted; secrets never read or echoed. |
| `--install-root` | Staged uninstall root for tests (default `/`). Must be an absolute path; relative values are rejected before any removal. |
| `--purge-data` | Remove `/var/lib/astranull` (bootstrap token, identity, local agent state). Default preserves this directory. |

Staged validation (no root):

```bash
agents/linux/uninstall.sh --install-root /tmp/astranull-staged
# Full removal including identity data:
agents/linux/uninstall.sh --install-root /tmp/astranull-staged --purge-data
```

## Systemd service

Shipped unit: `agents/linux/systemd/astranull-agent.service`. It loads `/etc/astranull/agent.env` (no secrets), sets `ASTRANULL_AGENT_IDENTITY=/var/lib/astranull/identity.json`, runs as `astranull`, and applies a baseline hardening profile (`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`, writable `/var/lib/astranull` only). Set `ASTRANULL_API_URL` to an HTTPS control-plane endpoint in production; localhost HTTP is developer-only via `--allow-insecure-localhost-api` or `ASTRANULL_ALLOW_INSECURE_LOCALHOST_API=1`. Registration identity is written under `/var/lib/astranull/` with directory mode `0700` and file mode `0600` (override with `--identity` or `ASTRANULL_AGENT_IDENTITY`).

## Docker install

Use cases:

- canary container,
- lab validation,
- quick PoC,
- container platform without Kubernetes.

Example:

```bash
docker run -d --name astranull-agent \
  --restart unless-stopped \
  -v astranull-data:/var/lib/astranull \
  -v /path/to/bootstrap-token:/var/lib/astranull/bootstrap-token:ro \
  -e ASTRANULL_BOOTSTRAP_TOKEN_FILE=/var/lib/astranull/bootstrap-token \
  -e ASTRANULL_API_URL=https://api.astranull.example \
  -e ASTRANULL_AGENT_NAME=prod-canary-01 \
  astranull/agent:0.2.0-production-readiness
```

For packet metadata capture, the container may need additional capabilities depending on observation mode. The UI should explain why and offer canary/log mode when privileged capabilities are not allowed.

## Helm install

```bash
helm repo add astranull https://charts.astranull.example
helm upgrade --install astranull-agent astranull/agent \
  --namespace astranull --create-namespace \
  --set bootstrapToken=<BOOTSTRAP_TOKEN> \
  --set mode=daemonset
```

## Uninstall

Generic Linux (repository script — preferred for tarball/generic installs):

```bash
sudo agents/linux/uninstall.sh
# Remove service and config but keep /var/lib/astranull for forensics or re-install:
sudo agents/linux/uninstall.sh
# Remove identity and bootstrap data as well:
sudo agents/linux/uninstall.sh --purge-data
```

Distro-native packages (built locally; apt/yum repo publishing and distro matrix validation remain release gates):

```bash
# prerm in .deb/.rpm stops astranull-agent.service before removal
sudo apt remove astranull-agent
# or
sudo yum remove astranull-agent
```

For generic tarball installs, prefer `uninstall.sh`. After `apt`/`yum` remove, use `--purge-data` semantics manually if `/var/lib/astranull` should be deleted (package scripts do not purge state by default).

Docker:

```bash
docker rm -f astranull-agent
```

Kubernetes:

```bash
helm uninstall astranull-agent -n astranull
```

UI should show revoke-agent button after uninstall.

## Completion criteria

Packaging is complete when install, upgrade, rollback, uninstall, signature verification, and health reporting work across supported deployment modes.
