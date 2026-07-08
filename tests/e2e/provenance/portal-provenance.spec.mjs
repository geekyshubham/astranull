import { expect, test } from '@playwright/test';
import {
  applyPortalProvenanceConnectorActive,
  applyPortalProvenanceConnectorDegraded,
  applyPortalProvenanceDnsLadderBaseline,
  applyPortalProvenanceDnsLadderExpanded,
  applyPortalProvenanceFindingsBaseline,
  applyPortalProvenanceFindingsExpanded,
  applyPortalProvenanceRemediationDelivered,
  applyPortalProvenanceRemediationOpen,
  applyPortalProvenanceSocQueueBaseline,
  applyPortalProvenanceSocQueueExpanded,
  applyPortalProvenanceWafPostureDrift,
  applyPortalProvenanceWafPostureProtected,
  PROVENANCE_DNS_LADDER,
  PROVENANCE_FINDINGS,
  PROVENANCE_REMEDIATION,
  PROVENANCE_SOC_QUEUE,
  PROVENANCE_WAF_CONNECTORS,
  PROVENANCE_WAF_POSTURE,
} from '../../fixtures/portal-baseline/provenance.mjs';
import { applyPortalBaselineReadinessBoost } from '../../fixtures/portal-baseline/readiness.mjs';
import { PORTAL_BASELINE_IDS } from '../../fixtures/portal-baseline/seed.mjs';
import {
  countOpenFindings,
  expectedReadinessScores,
  fetchPortalFinding,
  fetchPortalFindings,
  fetchPortalHighScaleQueue,
  fetchPortalReadinessScore,
  fetchPortalTargetDetail,
  fetchPortalVerificationLadder,
  fetchPortalWafCoverageSummary,
  getPortalPlaywrightBaseUrl,
  restartPortalPlaywrightServer,
  restartPortalPlaywrightWithReadinessPenalty,
  startPortalPlaywrightServer,
  stopPortalPlaywrightServer,
} from '../../helpers/portal-playwright-server.mjs';
import {
  gotoPortalRoute,
  injectPortalDevHeadersSession,
} from '../../helpers/portal-playwright-session.mjs';

test.describe('portal dynamic provenance', () => {
  test.afterAll(async () => {
    await stopPortalPlaywrightServer();
  });

  test('FT-PROV-dyn-01 dashboard readiness score updates after store mutation + server restart', async ({ page }) => {
    const { boostedScore, penalizedScore } = expectedReadinessScores();
    expect(boostedScore).toBeGreaterThan(penalizedScore);

    await startPortalPlaywrightServer({ mutate: applyPortalBaselineReadinessBoost });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialApiScore = await fetchPortalReadinessScore(baseUrl);
    expect(initialApiScore).toBe(boostedScore);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);
    await expect(page.getByText(String(initialApiScore), { exact: true }).first()).toBeVisible();

    await restartPortalPlaywrightWithReadinessPenalty();
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedApiScore = await fetchPortalReadinessScore(mutatedBaseUrl);
    expect(mutatedApiScore).toBe(penalizedScore);
    expect(mutatedApiScore).not.toBe(initialApiScore);

    await page.goto(`${mutatedBaseUrl}/app#dashboard`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(page.getByText(String(mutatedApiScore), { exact: true }).first()).toBeVisible();
    await expect(page.getByText(String(initialApiScore), { exact: true })).toHaveCount(0);
  });

  test('FT-PROV-dyn-02 findings tab count and pager update after open-findings mutation', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceFindingsBaseline });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialFindings = await fetchPortalFindings(baseUrl);
    expect(countOpenFindings(initialFindings)).toBe(PROVENANCE_FINDINGS.baselineOpenCount);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'findings', baseUrl);

    const openTab = page.getByRole('tab', { name: /Open/i });
    const pageSizeSelect = page.locator('.findings-pager select').last();
    await expect(openTab.locator('.ft-count')).toHaveText(String(PROVENANCE_FINDINGS.baselineOpenCount));
    await expect(page.locator('.findings-pager')).toContainText(`of ${PROVENANCE_FINDINGS.baselineOpenCount}`);
    for (const title of PROVENANCE_FINDINGS.baselineOnlyTitles) {
      await expect(page.getByText(title, { exact: true })).toBeVisible();
    }
    for (const title of PROVENANCE_FINDINGS.mutatedOnlyTitles) {
      await expect(page.getByText(title, { exact: true })).toHaveCount(0);
    }

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceFindingsExpanded });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedFindings = await fetchPortalFindings(mutatedBaseUrl);
    expect(countOpenFindings(mutatedFindings)).toBe(PROVENANCE_FINDINGS.mutatedOpenCount);

    await page.goto(`${mutatedBaseUrl}/app#findings`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(openTab.locator('.ft-count')).toHaveText(String(PROVENANCE_FINDINGS.mutatedOpenCount));
    await expect(page.locator('.findings-pager')).toContainText(`of ${PROVENANCE_FINDINGS.mutatedOpenCount}`);
    await pageSizeSelect.selectOption('12');
    for (const title of PROVENANCE_FINDINGS.mutatedOnlyTitles) {
      await expect(page.getByText(title, { exact: true })).toBeVisible();
    }
  });

  test('FT-PROV-dyn-03 target-group ladder and verification chips update after DNS mutation', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceDnsLadderBaseline });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialLadder = await fetchPortalVerificationLadder(undefined, baseUrl);
    const initialDns = initialLadder.steps.find((step) => step.id === 'dns_verified');
    expect(initialDns?.count).toBe(PROVENANCE_DNS_LADDER.baselineDnsVerified);
    expect(initialDns?.total).toBe(PROVENANCE_DNS_LADDER.total);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-group-detail', baseUrl);

    const ladderMeta = page.locator('.verify-ladder .vl-meta');
    const promotedTargetRow = page.locator('tr').filter({ hasText: PROVENANCE_DNS_LADDER.promotedTargetValue });
    await expect(ladderMeta.filter({ hasText: `${PROVENANCE_DNS_LADDER.baselineDnsVerified} of ${PROVENANCE_DNS_LADDER.total}` })).toBeVisible();
    await expect(promotedTargetRow).toContainText('agent_verified');

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceDnsLadderExpanded });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedLadder = await fetchPortalVerificationLadder(undefined, mutatedBaseUrl);
    const mutatedDns = mutatedLadder.steps.find((step) => step.id === 'dns_verified');
    expect(mutatedDns?.count).toBe(PROVENANCE_DNS_LADDER.mutatedDnsVerified);

    await page.goto(`${mutatedBaseUrl}/app#target-group-detail?id=${encodeURIComponent(PORTAL_BASELINE_IDS.targetGroupId)}`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(ladderMeta.filter({ hasText: `${PROVENANCE_DNS_LADDER.mutatedDnsVerified} of ${PROVENANCE_DNS_LADDER.total}` })).toBeVisible();
    await expect(promotedTargetRow).toContainText('dns_verified');
  });

  test('FT-PROV-dyn-04 target detail WAF posture updates after posture mutation', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceWafPostureProtected });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialDetail = await fetchPortalTargetDetail(PROVENANCE_WAF_POSTURE.targetId, baseUrl);
    expect(initialDetail.waf_posture?.posture).toBe(PROVENANCE_WAF_POSTURE.baselinePosture);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'target-detail', baseUrl);

    const posturePanel = page.locator('.content').filter({ has: page.getByRole('heading', { name: 'WAF posture' }) });
    await expect(posturePanel.getByText(PROVENANCE_WAF_POSTURE.baselinePosture, { exact: true }).first()).toBeVisible();
    await expect(posturePanel.locator('pre.codeblock')).toContainText(`"posture": "${PROVENANCE_WAF_POSTURE.baselinePosture}"`);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceWafPostureDrift });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedDetail = await fetchPortalTargetDetail(PROVENANCE_WAF_POSTURE.targetId, mutatedBaseUrl);
    expect(mutatedDetail.waf_posture?.posture).toBe(PROVENANCE_WAF_POSTURE.mutatedPosture);
    expect(mutatedDetail.waf_posture?.drift_reason).toBe(PROVENANCE_WAF_POSTURE.mutatedDriftReason);

    await page.goto(`${mutatedBaseUrl}/app#target-detail?id=${encodeURIComponent(PROVENANCE_WAF_POSTURE.targetId)}`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(posturePanel.getByText(PROVENANCE_WAF_POSTURE.mutatedPosture, { exact: true }).first()).toBeVisible();
    await expect(posturePanel.getByText(PROVENANCE_WAF_POSTURE.mutatedDriftReason, { exact: true })).toBeVisible();
    await expect(posturePanel.locator('pre.codeblock')).toContainText(`"posture": "${PROVENANCE_WAF_POSTURE.mutatedPosture}"`);
    await expect(posturePanel.locator('pre.codeblock')).toContainText(`"drift_reason": "${PROVENANCE_WAF_POSTURE.mutatedDriftReason}"`);
  });

  test('FT-PROV-dyn-05 dashboard WAF connectors tile updates after connector status mutation', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceConnectorActive });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialSummary = await fetchPortalWafCoverageSummary(baseUrl);
    expect(initialSummary.connectors_active).toBe(PROVENANCE_WAF_CONNECTORS.baselineActive);
    expect(initialSummary.connectors_degraded).toBe(PROVENANCE_WAF_CONNECTORS.baselineDegraded);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'dashboard', baseUrl);

    const connectorsTile = page.locator('.dash-waf-grid .dw-kpi').filter({ hasText: 'Connectors' });
    await expect(connectorsTile.locator('.dw-value')).toHaveText(String(PROVENANCE_WAF_CONNECTORS.baselineActive));
    await expect(connectorsTile.locator('.dw-note')).toContainText('healthy');

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceConnectorDegraded });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedSummary = await fetchPortalWafCoverageSummary(mutatedBaseUrl);
    expect(mutatedSummary.connectors_active).toBe(PROVENANCE_WAF_CONNECTORS.mutatedActive);
    expect(mutatedSummary.connectors_degraded).toBe(PROVENANCE_WAF_CONNECTORS.mutatedDegraded);

    await page.goto(`${mutatedBaseUrl}/app#dashboard`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(connectorsTile.locator('.dw-value')).toHaveText(String(PROVENANCE_WAF_CONNECTORS.mutatedActive));
    await expect(connectorsTile.locator('.dw-note')).toContainText(`${PROVENANCE_WAF_CONNECTORS.mutatedDegraded} degraded`);
  });

  test('FT-PROV-dyn-06 finding remediation badge and delivered_via line update after mutation', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceRemediationOpen });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialFinding = await fetchPortalFinding(PROVENANCE_REMEDIATION.findingId, baseUrl);
    expect(initialFinding.remediation?.state).toBe(PROVENANCE_REMEDIATION.baselineState);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'finding-detail', baseUrl);

    const remediationCard = page.locator('[data-od-id="finding-remediation"]');
    await expect(remediationCard.getByText(PROVENANCE_REMEDIATION.baselineState, { exact: true })).toBeVisible();
    await expect(remediationCard).toContainText(PROVENANCE_REMEDIATION.baselineDescription);
    await expect(remediationCard).not.toContainText(PROVENANCE_REMEDIATION.mutatedDescription);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceRemediationDelivered });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedFinding = await fetchPortalFinding(PROVENANCE_REMEDIATION.findingId, mutatedBaseUrl);
    expect(mutatedFinding.remediation?.state).toBe(PROVENANCE_REMEDIATION.mutatedState);
    expect(mutatedFinding.remediation?.delivered_via).toBe(PROVENANCE_REMEDIATION.deliveredVia);

    await page.goto(`${mutatedBaseUrl}/app#finding-detail?id=${encodeURIComponent(PROVENANCE_REMEDIATION.findingId)}`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(remediationCard.getByText(PROVENANCE_REMEDIATION.mutatedState, { exact: true })).toBeVisible();
    await expect(remediationCard).toContainText(PROVENANCE_REMEDIATION.mutatedDescription);
    await expect(remediationCard).not.toContainText(PROVENANCE_REMEDIATION.baselineDescription);
  });

  test('FT-PROV-dyn-07 SOC-gated inline queue row appears after high-scale request mutation', async ({ page }) => {
    await startPortalPlaywrightServer({ mutate: applyPortalProvenanceSocQueueBaseline });
    const baseUrl = getPortalPlaywrightBaseUrl();
    const initialQueue = await fetchPortalHighScaleQueue(baseUrl);
    expect(initialQueue).toHaveLength(1);
    expect(initialQueue[0]?.id).toBe(PROVENANCE_SOC_QUEUE.baselineRequestId);

    await injectPortalDevHeadersSession(page);
    await gotoPortalRoute(page, 'runs', baseUrl);

    const queueTable = page.locator('.runs-soc-gate table');
    await expect(queueTable.getByText(PROVENANCE_SOC_QUEUE.baselineRequestId)).toBeVisible();
    await expect(queueTable.getByText(PROVENANCE_SOC_QUEUE.addedRequestId)).toHaveCount(0);

    await restartPortalPlaywrightServer({ mutate: applyPortalProvenanceSocQueueExpanded });
    const mutatedBaseUrl = getPortalPlaywrightBaseUrl();
    const mutatedQueue = await fetchPortalHighScaleQueue(mutatedBaseUrl);
    expect(mutatedQueue).toHaveLength(2);
    expect(mutatedQueue.some((row) => row.id === PROVENANCE_SOC_QUEUE.addedRequestId)).toBe(true);

    await page.goto(`${mutatedBaseUrl}/app#runs`, { waitUntil: 'networkidle', timeout: 60_000 });
    await expect(queueTable.getByText(PROVENANCE_SOC_QUEUE.baselineRequestId)).toBeVisible();
    await expect(queueTable.getByText(PROVENANCE_SOC_QUEUE.addedRequestId)).toBeVisible();
  });
});