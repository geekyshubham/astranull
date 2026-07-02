import { runControlPlaneProcess, redactStartupErrorMessage } from './startup.mjs';

const env = process.env;

runControlPlaneProcess({ env }).catch((err) => {
  console.error(`AstraNull startup failed: ${redactStartupErrorMessage(err, env)}`);
  process.exit(1);
});