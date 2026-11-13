import { randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';

const domain = process.argv[2]?.toLowerCase();
// 公网 DNS 域名；不接受 URL、端口、路径或 Compose 插值字符。
if (!domain || domain.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) {
  console.error('Usage: npm run configure -- mcp.example.com');
  process.exit(1);
}
try {
  await writeFile(new URL('../.env', import.meta.url),
    `MCP_DOMAIN=${domain}\nMCP_AUTH_TOKEN=${randomBytes(32).toString('hex')}\n`,
    { flag: 'wx', mode: 0o600 });
  console.log(`Created .env with a random token. Endpoint: https://${domain}/mcp`);
  console.log('Next: docker compose up -d --build. Read MCP_AUTH_TOKEN from .env when configuring your client.');
} catch (error) {
  console.error(error.code === 'EEXIST' ? '.env already exists; edit it directly to preserve your token.' : 'Could not write .env');
  process.exitCode = 1;
}
