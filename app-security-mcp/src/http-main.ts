import { createHttpApp, readConfig } from './http.js';

try {
  const config = readConfig();
  const app = createHttpApp(config);
  app.server.on('error', (error: NodeJS.ErrnoException) => {
    console.error(`[app-security-mcp] listen failed: ${error.code ?? 'unknown'}`);
    process.exit(1);
  });
  app.server.listen(config.port, config.host, () => {
    console.error(`[app-security-mcp] HTTP listening on ${config.host}:${config.port}/mcp`);
  });
  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    const deadline = setTimeout(() => process.exit(1), 10_000);
    deadline.unref();
    try {
      await app.close();
      clearTimeout(deadline);
    } catch {
      console.error('[app-security-mcp] shutdown failed');
      process.exitCode = 1;
    }
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
} catch (error) {
  console.error(`[app-security-mcp] configuration error: ${(error as Error).message}`);
  process.exitCode = 1;
}
