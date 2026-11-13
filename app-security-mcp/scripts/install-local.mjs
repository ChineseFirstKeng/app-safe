import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile, rename, access } from 'node:fs/promises';
import { homedir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const entry = join(root, 'dist/index.js');
await access(entry); // Build must succeed before replacing the connection.
const home = resolve(process.env.CODEX_HOME || join(homedir(), '.codex'));
const backup = join(home, 'backups/app-security', `local-${Date.now()}`);
await mkdir(backup, { recursive: true, mode: 0o700 });
const configPath = join(home, 'config.toml');
let original;
try {
  original = await readFile(configPath);
  await writeFile(join(backup, 'config.toml'), original, { mode: 0o600, flag: 'wx' });
} catch (error) { if (error.code !== 'ENOENT') throw error; }
let moved = false;
const skill = join(home, 'skills/app-security');
try {
  try { await rename(skill, join(backup, 'skill')); moved = true; }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  execFileSync('codex', ['mcp', 'remove', 'app-security'], { stdio: 'pipe' });
  execFileSync('codex', ['mcp', 'add', 'app-security', '--', process.execPath, entry], { stdio: 'pipe' });
} catch {
  if (original) await writeFile(configPath, original, { mode: 0o600 });
  if (moved) await rename(join(backup, 'skill'), skill);
  throw new Error('本地 MCP 安装失败，已有配置已恢复；未输出凭证。');
}
console.log(`本地 app-security MCP 已配置：${entry}\n备份：${backup}\n不安装本地 Skill。重新连接或重启 Codex 后使用。`);
