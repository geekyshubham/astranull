import { loadRuntimeConfig } from './config.mjs';
import { createServer } from './server.mjs';
import { createPostgresRuntime } from './persistence/postgres/runtime.mjs';
import { redactDatabaseUrlInMessage } from './lib/pgErrorRedact.mjs';

export { redactDatabaseUrlInMessage as redactStartupErrorMessage };

/**
 * @param {{
 *   env?: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   runtimeConfig?: ReturnType<typeof loadRuntimeConfig>,
 *   services?: Record<string, unknown>,
 *   createPostgresRuntime?: typeof createPostgresRuntime,
 *   createServer?: typeof createServer,
 *   postgresRuntimeOptions?: Parameters<typeof createPostgresRuntime>[1],
 *   listen?: boolean,
 *   port?: number,
 * }} [options]
 */
export async function startControlPlane(options = {}) {
  const env = options.env ?? process.env;
  const runtimeConfig = options.runtimeConfig ?? loadRuntimeConfig(env);
  const createPostgresRuntimeFn = options.createPostgresRuntime ?? createPostgresRuntime;
  const createServerFn = options.createServer ?? createServer;

  /** @type {Awaited<ReturnType<typeof createPostgresRuntime>> | null} */
  let persistenceRuntime = null;
  /** @type {Record<string, unknown> | undefined} */
  let services = options.services;

  try {
    if (runtimeConfig.persistenceMode === 'postgres') {
      persistenceRuntime = await createPostgresRuntimeFn(env, options.postgresRuntimeOptions);
      services = { ...persistenceRuntime.services, ...(options.services ?? {}) };
    }

    const server = createServerFn({
      env,
      runtimeConfig,
      services,
      runtimeHealth: persistenceRuntime?.health ?? options.runtimeHealth,
    });

    const close = async () => {
      await new Promise((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      if (persistenceRuntime) {
        await persistenceRuntime.close();
      }
    };

    return {
      server,
      runtimeConfig,
      persistenceRuntime,
      close,
    };
  } catch (err) {
    if (persistenceRuntime) {
      try {
        await persistenceRuntime.close();
      } catch {
        // ignore cleanup errors; preserve original failure
      }
    }
    throw err;
  }
}

/**
 * CLI entry: load config, bootstrap persistence + HTTP server, register signal handlers.
 *
 * @param {{
 *   env?: NodeJS.ProcessEnv | Record<string, string | undefined>,
 *   port?: number,
 *   createPostgresRuntime?: typeof createPostgresRuntime,
 *   createServer?: typeof createServer,
 * }} [options]
 */
export async function runControlPlaneProcess(options = {}) {
  const env = options.env ?? process.env;
  const port = Number(options.port ?? env.PORT ?? 3000);
  const app = await startControlPlane({
    env,
    createPostgresRuntime: options.createPostgresRuntime,
    createServer: options.createServer,
  });

  let shuttingDown = false;

  const shutdown = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`AstraNull shutting down (${signal})`);
    app
      .close()
      .then(() => {
        console.log('AstraNull stopped');
        process.exit(0);
      })
      .catch((err) => {
        console.error(`AstraNull shutdown error: ${redactDatabaseUrlInMessage(err, env)}`);
        process.exit(1);
      });
    setTimeout(() => {
      console.error('AstraNull shutdown grace exceeded; exiting');
      process.exit(1);
    }, app.runtimeConfig.shutdownGraceMs).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  await new Promise((resolve, reject) => {
    app.server.once('error', reject);
    app.server.listen(port, () => {
      app.server.off('error', reject);
      resolve();
    });
  });

  console.log(
    `AstraNull listening on http://localhost:${port} (auth_mode=${app.runtimeConfig.authMode})`,
  );

  return app;
}