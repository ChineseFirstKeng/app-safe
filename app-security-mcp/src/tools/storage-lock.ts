import { mkdir, lstat, rm } from 'node:fs/promises';
import { join } from 'node:path';

// Cross-process coordination. Fail closed if a process exits while holding a lock;
// never infer ownership from a reused PID or remove a live process's lock.
export async function withArtifactLock<T>(root: string, artifactId: string, action: () => Promise<T>): Promise<T> {
  if (!/^[a-f0-9]{32}$/.test(artifactId)) throw new Error('invalid_artifact_id');
  const locks = join(root, '_locks');
  await mkdir(locks, { recursive: true, mode: 0o700 });
  if ((await lstat(locks)).isSymbolicLink()) throw new Error('invalid_lock_storage');
  const path = join(locks, artifactId);
  try { await mkdir(path, { mode: 0o700 }); }
  catch { throw new Error('artifact_operation_busy'); }
  try { return await action(); }
  finally { await rm(path, { recursive: true, force: true }); }
}
