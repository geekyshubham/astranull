import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { LOCAL_STAGING_ENVIRONMENT } from '../../scripts/lib/localStaging.mjs';
import { parseLocalStagingStackArgs } from '../../scripts/local-staging-stack.mjs';
import { isLocalStagingEnvironment } from '../../scripts/lib/localStaging.mjs';
import {
  isLocalStagingSimulatorEnvironment,
  isPromotionEligibleEnvironment,
} from '../../scripts/submit-staging-evidence.mjs';

describe('local staging stack', () => {
  it('parses stack commands', () => {
    assert.deepEqual(parseLocalStagingStackArgs(['all', '--api-port', '3001']), {
      command: 'all',
      port: 54329,
      apiPort: 3001,
      timeoutMs: 120_000,
      baseUrl: 'http://127.0.0.1:3000',
      help: false,
    });
  });

  it('recognizes the local-staging environment label', () => {
    assert.equal(isLocalStagingEnvironment(LOCAL_STAGING_ENVIRONMENT), true);
    assert.equal(isLocalStagingSimulatorEnvironment('local-staging'), true);
    assert.equal(isPromotionEligibleEnvironment('local-staging', { allowLocalStaging: true }), true);
    assert.equal(isPromotionEligibleEnvironment('local-staging'), false);
  });
});