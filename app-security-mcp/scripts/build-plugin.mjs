import { build } from 'esbuild';
import { cp, mkdir, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
const root = fileURLToPath(new URL('..', import.meta.url));
const market = join(root, 'artifacts/plugin-marketplace');
const output = join(market, 'plugins/app-security');
await rm(market, { recursive: true, force: true });
await mkdir(output, { recursive: true });
await cp(join(root, 'plugin'), output, { recursive: true });
await cp(join(root, 'workers'), join(output, 'workers'), { recursive: true, filter: source => !source.split('/').includes('__pycache__') && !source.endsWith('.pyc') });
await cp(join(root, 'skills'), join(output, 'skills'), { recursive: true });
await build({
  entryPoints: [join(root, 'src/index.ts')], outfile: join(output, 'dist/index.mjs'),
  bundle: true, platform: 'node', format: 'esm', target: 'node22',
  banner: { js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);" },
});
await mkdir(join(market, '.agents/plugins'), { recursive: true });
await writeFile(join(market, '.agents/plugins/marketplace.json'), JSON.stringify({
  name: 'app-security-local', interface: { displayName: 'App Security 本地开发' },
  plugins: [{ name: 'app-security', source: { source: 'local', path: './plugins/app-security' },
    policy: { installation: 'AVAILABLE', authentication: 'ON_INSTALL' }, category: 'Developer Tools' }],
}, null, 2) + '\n');
console.log(`插件市场已生成：${market}`);

await mkdir(join(market, '.claude-plugin'), { recursive: true });
await writeFile(join(market, '.claude-plugin/marketplace.json'), JSON.stringify({
  name: 'app-security-local', owner: { name: 'App Security' },
  plugins: [{ name: 'app-security', source: './plugins/app-security', description: 'Local APK/IPA hardcoding candidate analysis' }],
}, null, 2) + '\n');
