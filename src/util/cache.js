import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';

const baseDir =
  process.env.IAMSECURE_CACHE_DIR ||
  path.join(process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'), 'iamsecure');

const fileFor = (ns, key) =>
  path.join(baseDir, ns, crypto.createHash('sha256').update(key).digest('hex').slice(0, 40) + '.json');

/** Returns undefined on miss, expiry or any read error. */
export function cacheGet(ns, key, maxAgeMs) {
  if (process.env.IAMSECURE_NO_CACHE) return undefined;
  const file = fileFor(ns, key);
  try {
    if (maxAgeMs && Date.now() - fs.statSync(file).mtimeMs > maxAgeMs) return undefined;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return undefined;
  }
}

export function cacheSet(ns, key, value) {
  const file = fileFor(ns, key);
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(value));
  } catch {
    // A cache that can't be written is just a slower scan.
  }
}

export const cacheDir = baseDir;
