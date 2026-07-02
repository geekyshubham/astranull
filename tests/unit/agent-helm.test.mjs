import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  AGENT_HELM_CHART_DIR,
  assertHelmTemplateSecurity,
  buildHelmTemplateCommand,
  isHelmAvailable,
  loadHelmTemplates,
  loadHelmValues,
  renderAgentHelmManifests,
  splitYamlDocuments,
} from '../../scripts/render-agent-helm.mjs';

function manifestKinds(manifests) {
  return manifests.map((doc) => {
    const match = doc.match(/^kind:\s*(\S+)/m);
    return match ? match[1] : null;
  });
}

describe('agent helm chart', () => {
  it('values default to HTTPS apiUrl and daemonset mode', () => {
    const values = loadHelmValues();
    assert.match(values, /^apiUrl: https:\/\//m);
    assert.match(values, /^mode: daemonset/m);
    assert.match(values, /bootstrapToken: ""/m);
    assert.match(values, /persistence:\n  type: hostPath/m);
    assert.match(values, /hostPath: \/var\/lib\/astranull/m);
    assert.match(values, /canaryListen:\n  enabled: false/m);
    assert.doesNotMatch(values, /bootstrapToken: "<BOOTSTRAP_TOKEN>"/);
  });

  it('templates enforce non-root security and bootstrap token file mount', () => {
    const templates = loadHelmTemplates();
    const security = assertHelmTemplateSecurity(templates);
    assert.equal(security.ok, true, security.issues.join('; '));
    assert.match(templates['daemonset.yaml'], /kind: DaemonSet/);
    assert.match(templates['daemonset.yaml'], /hostPath:/);
    assert.match(templates['daemonset.yaml'], /persistentVolumeClaim:/);
    assert.match(templates['deployment.yaml'], /kind: Deployment/);
    assert.match(templates['deployment.yaml'], /hostPath:/);
    assert.match(templates['deployment.yaml'], /persistentVolumeClaim:/);
    assert.match(templates['secret.yaml'], /kind: Secret/);
    assert.match(templates['secret.yaml'], /\{\{- if \.Values\.bootstrapToken \}\}/);
  });

  it('builds helm template command with set values', () => {
    const command = buildHelmTemplateCommand({
      sets: {
        mode: 'deployment',
        apiUrl: 'https://api.test.example',
        bootstrapToken: 'ast_test_token_value',
        'agent.name': 'k8s-canary-01',
      },
    });
    assert.equal(command.cmd, 'helm');
    assert.ok(command.args.includes('template'));
    assert.ok(command.args.includes(AGENT_HELM_CHART_DIR));
    assert.ok(command.args.includes('mode=deployment'));
    assert.ok(command.args.includes('bootstrapToken=ast_test_token_value'));
  });

  it('renders deployment mode with Secret and no privileged agent container when helm is available', () => {
    if (!isHelmAvailable()) {
      return;
    }

    const rendered = renderAgentHelmManifests({
      sets: {
        mode: 'deployment',
        apiUrl: 'https://api.test.example',
        bootstrapToken: 'ast_test_token_value',
        'agent.name': 'k8s-canary-01',
        'canaryListen.enabled': 'true',
        'canaryListen.port': '18080',
      },
    });
    assert.equal(rendered.ok, true);
    const kinds = manifestKinds(rendered.manifests);
    assert.ok(kinds.includes('Secret'));
    assert.ok(kinds.includes('Deployment'));
    assert.equal(kinds.includes('DaemonSet'), false);

    const deployment = rendered.manifests.find((doc) => /kind:\s*Deployment/m.test(doc));
    assert.ok(deployment);
    assert.match(deployment, /runAsNonRoot: true/);
    assert.match(deployment, /runAsUser: 10001/);
    assert.match(deployment, /ASTRANULL_BOOTSTRAP_TOKEN_FILE/);
    assert.match(deployment, /hostPath:/);
    assert.match(deployment, /path: \/var\/lib\/astranull/);
    assert.match(deployment, /https:\/\/api\.test\.example/);
    assert.match(deployment, /--name/);
    assert.match(deployment, /k8s-canary-01/);
    assert.match(deployment, /--canary-listen/);
    assert.doesNotMatch(deployment, /privileged:\s*true/);
    assert.doesNotMatch(deployment, /value:\s*ast_test_token_value/);
    assert.doesNotMatch(deployment, /kind:\s*DaemonSet/);
  });

  it('renders daemonset mode without Secret when bootstrapToken is unset', () => {
    if (!isHelmAvailable()) {
      return;
    }

    const rendered = renderAgentHelmManifests({
      sets: {
        mode: 'daemonset',
        bootstrapToken: '',
      },
    });
    const kinds = manifestKinds(rendered.manifests);
    assert.ok(kinds.includes('DaemonSet'));
    assert.equal(kinds.includes('Secret'), false);
    assert.equal(kinds.includes('Deployment'), false);
  });

  it('renders pvc persistence when an existing claim is configured', () => {
    if (!isHelmAvailable()) {
      return;
    }

    const rendered = renderAgentHelmManifests({
      sets: {
        'persistence.type': 'pvc',
        'persistence.existingClaim': 'astranull-agent-state',
      },
    });
    const daemonset = rendered.manifests.find((doc) => /kind:\s*DaemonSet/m.test(doc));
    assert.ok(daemonset);
    assert.match(daemonset, /persistentVolumeClaim:/);
    assert.match(daemonset, /claimName: astranull-agent-state/);
    assert.doesNotMatch(daemonset, /emptyDir:\s*\{\}/);
  });

  it('splitYamlDocuments separates multi-doc helm output', () => {
    const docs = splitYamlDocuments('apiVersion: v1\nkind: Secret\n---\nkind: Deployment\n');
    assert.equal(docs.length, 2);
    assert.match(docs[0], /kind: Secret/);
    assert.match(docs[1], /kind: Deployment/);
  });
});
