import { useState } from 'react';
import { AnchorButton, Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Tabs } from '../ui/tabs';
import { agentInstallApiBase } from '../../lib/agent-helpers';
import { resolveAgentReleaseMetadata } from '../../lib/agent-release-metadata';
import type { DataItem, PortalData } from '../../lib/types';

const INSTALL_TABS = [
  { id: 'linux', label: 'Linux one-liner' },
  { id: 'container', label: 'Container image' },
  { id: 'helm', label: 'Kubernetes/Helm' },
  { id: 'deb', label: 'Debian/Ubuntu' },
  { id: 'rpm', label: 'RHEL/Fedora' },
  { id: 'tarball', label: 'Air-gapped tarball' },
  { id: 'puppet', label: 'Puppet' },
  { id: 'ansible', label: 'Ansible' }
] as const;

type InstallTabId = (typeof INSTALL_TABS)[number]['id'];

export function AgentInstallMatrix({
  data,
  tokenSecret,
  onCreateToken,
  createBusy,
  actionsDisabled
}: {
  data: PortalData;
  tokenSecret: string;
  onCreateToken: () => void;
  createBusy: boolean;
  actionsDisabled: boolean;
}) {
  const [tab, setTab] = useState<InstallTabId>('linux');
  const release = resolveAgentReleaseMetadata(data.releaseEvidence);
  const apiBase = agentInstallApiBase();
  const installToken = tokenSecret || '<BOOTSTRAP_TOKEN>';
  const tabOptions = INSTALL_TABS.map((item) => ({ id: item.id, label: item.label }));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Deploy an agent</CardTitle>
        <CardDescription>Outbound-only install paths. Release metadata is sourced from production release evidence records.</CardDescription>
      </CardHeader>
      <CardContent className="stack-tight">
        <div className="release-metadata-bar kv-list kv-list--compact" aria-label="Agent release metadata">
          <div><span>Release</span><strong className="mono" title="From agent_install_matrix / agent_sbom_provenance evidence">{release.version}</strong></div>
          <div><span>Image digest</span><strong className="mono" title="Package SHA-256 from SBOM evidence">{release.digest}</strong></div>
          <div><span>Cosign</span><strong title="Signature status from release evidence">{release.cosignStatus}</strong></div>
          <div>
            <span>SBOM</span>
            {release.sbomUri !== '—' ? <AnchorButton size="sm" variant="ghost" href={release.sbomUri}>CycloneDX 1.5</AnchorButton> : <strong>—</strong>}
          </div>
          <div>
            <span>Provenance</span>
            {release.provenanceUri !== '—' ? <AnchorButton size="sm" variant="ghost" href={release.provenanceUri}>SLSA v1</AnchorButton> : <strong>—</strong>}
          </div>
        </div>
        <div className="row-actions page-toolbar">
          <Button loading={createBusy} disabled={actionsDisabled} onClick={onCreateToken}>Create bootstrap token</Button>
        </div>
        <Tabs value={tab} options={tabOptions} onChange={(value) => setTab(value as InstallTabId)} className="tabs-wrap" />
        {tab === 'linux' ? (
          <pre className="codeblock">{`curl -fsSL ${apiBase}/agents/install.sh \\
  | sudo ASTRANULL_API_URL="${apiBase}" \\
       ASTRANULL_BOOTSTRAP_TOKEN="${installToken}" bash`}</pre>
        ) : null}
        {tab === 'container' ? (
          <pre className="codeblock">{`docker run -d --name astranull-agent \\
  -e ASTRANULL_API_URL="${apiBase}" \\
  -e ASTRANULL_BOOTSTRAP_TOKEN="${installToken}" \\
  ${release.packageName}:latest`}</pre>
        ) : null}
        {tab === 'helm' ? (
          <pre className="codeblock">{`helm upgrade --install astranull-agent ./charts/agent \\
  --namespace astranull --create-namespace \\
  --set apiUrl="${apiBase}" \\
  --set image.tag="${release.version}" \\
  --set bootstrapToken="${installToken}"`}</pre>
        ) : null}
        {tab === 'deb' ? (
          <pre className="codeblock">{`curl -fsSL -O ${apiBase}/agents/${release.packageName}_${release.version}_amd64.deb
sudo dpkg -i ${release.packageName}_${release.version}_amd64.deb
sudo install -m 0640 /dev/stdin /etc/astranull/agent.env <<'EOF'
ASTRANULL_API_URL=${apiBase}
ASTRANULL_BOOTSTRAP_TOKEN=${installToken}
EOF
sudo systemctl enable --now astranull-agent`}</pre>
        ) : null}
        {tab === 'rpm' ? (
          <pre className="codeblock">{`curl -fsSL -O ${apiBase}/agents/${release.packageName}-${release.version}.noarch.rpm
sudo dnf install ./${release.packageName}-${release.version}.noarch.rpm
sudo systemctl enable --now astranull-agent`}</pre>
        ) : null}
        {tab === 'tarball' ? (
          <pre className="codeblock">{`curl -fsSL -O ${apiBase}/agents/${release.packageName}-${release.version}.tar.gz
curl -fsSL -O ${apiBase}/agents/${release.packageName}-${release.version}.manifest.json
curl -fsSL -O ${apiBase}/agents/${release.packageName}-${release.version}.manifest.sig
# Verify manifest signature, then extract to /opt/astranull`}</pre>
        ) : null}
        {tab === 'puppet' ? (
          <pre className="codeblock">{`class { 'astranull::agent':
  api_url       => '${apiBase}',
  bootstrap     => Sensitive('${installToken}'),
  package_digest => '${release.digest}',
  outbound_only => true,
}`}</pre>
        ) : null}
        {tab === 'ansible' ? (
          <pre className="codeblock">{`- name: Install AstraNull agent
  ansible.builtin.include_role:
    name: astranull.agent
  vars:
    astranull_api_url: "${apiBase}"
    astranull_bootstrap_token: "{{ vault_bootstrap_token }}"
    astranull_package_digest: "${release.digest}"`}</pre>
        ) : null}
        {tokenSecret ? <p className="muted">One-time token shown. It will not be displayed again after refresh.</p> : null}
      </CardContent>
    </Card>
  );
}