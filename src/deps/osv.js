import { fetchJson, mapLimit } from '../util/http.js';
import { cacheGet, cacheSet } from '../util/cache.js';
import { compareVersions } from '../util/semver.js';
import { cvssScore, levelFromScore, scoreFromLabel } from './cvss.js';

const OSV = 'https://api.osv.dev/v1';
const BATCH = 500;

/**
 * Look up every package against OSV.dev (which aggregates GitHub Advisories, npm, PyPA, Packagist, …).
 * @param {{name:string, version:string, ecosystem:string}[]} pkgs
 * @returns {Promise<Map<string, any[]>>} "ecosystem:name@version" → full OSV records
 */
export async function queryOsv(pkgs, { onProgress } = {}) {
  const idsByPkg = new Map();
  const wanted = new Map(); // id → modified

  for (let i = 0; i < pkgs.length; i += BATCH) {
    const chunk = pkgs.slice(i, i + BATCH);
    const res = await fetchJson(`${OSV}/querybatch`, {
      method: 'POST',
      body: { queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) },
    });
    await Promise.all(
      (res.results ?? []).map(async (r, j) => {
        let vulns = r.vulns ?? [];
        // A package with a very long advisory history gets paginated; follow it.
        for (let token = r.next_page_token; token; ) {
          const p = chunk[j];
          const more = await fetchJson(`${OSV}/query`, {
            method: 'POST',
            body: { package: { name: p.name, ecosystem: p.ecosystem }, version: p.version, page_token: token },
          });
          vulns = vulns.concat(more.vulns ?? []);
          token = more.next_page_token;
        }
        if (!vulns.length) return;
        idsByPkg.set(pkgId(chunk[j]), vulns.map((v) => v.id));
        for (const v of vulns) wanted.set(v.id, v.modified ?? '');
      }),
    );
    onProgress?.(Math.min(i + BATCH, pkgs.length), pkgs.length);
  }

  const details = new Map();
  await mapLimit([...wanted], 12, async ([id, modified]) => {
    const cached = cacheGet('osv', id);
    if (cached && (!modified || cached.modified === modified)) return details.set(id, cached);
    const full = await fetchJson(`${OSV}/vulns/${encodeURIComponent(id)}`);
    cacheSet('osv', id, full);
    details.set(id, full);
  });

  const out = new Map();
  for (const [key, ids] of idsByPkg) out.set(key, ids.map((id) => details.get(id)).filter(Boolean));
  return out;
}

export const pkgId = (p) => `${p.ecosystem}:${p.name}@${p.version}`;

/** Flatten an OSV record into what the report needs, for one affected package/version. */
export function normalizeVuln(v, pkg) {
  const sev = (v.severity ?? []).find((s) => s.type === 'CVSS_V3') ?? (v.severity ?? [])[0];
  const cvss = sev ? cvssScore(sev.score) : null;
  const affected = (v.affected ?? []).filter(
    (a) => a.package?.name === pkg.name && a.package?.ecosystem?.toLowerCase() === pkg.ecosystem.toLowerCase(),
  );
  const label = v.database_specific?.severity ?? affected.find((a) => a.ecosystem_specific?.severity)?.ecosystem_specific.severity;
  const malicious = v.id.startsWith('MAL-');
  const score = malicious ? 10 : (cvss?.score ?? scoreFromLabel(label) ?? 5);

  return {
    id: v.id,
    aliases: v.aliases ?? [],
    summary: v.summary || firstLine(v.details) || v.id,
    details: (v.details ?? '').slice(0, 4000),
    published: v.published,
    modified: v.modified,
    url: `https://osv.dev/vulnerability/${v.id}`,
    references: (v.references ?? []).slice(0, 6).map((r) => r.url),
    cwes: v.database_specific?.cwe_ids ?? [],
    cvss: cvss && { vector: sev.score, version: cvss.version, score: cvss.score, metrics: cvss.metrics },
    severityScore: score,
    severity: levelFromScore(score),
    fixedIn: fixedVersion(affected, pkg.version),
    malicious,
  };
}

/** Prefer the fix of the range that actually contains `current` (e.g. a 13.x backport over 15.x). */
function fixedVersion(affected, current) {
  const later = [];
  for (const range of affected.flatMap((a) => a.ranges ?? [])) {
    let introduced = null;
    for (const e of range.events ?? []) {
      if (e.introduced !== undefined) introduced = e.introduced;
      if (e.fixed === undefined) continue;
      const inRange = (introduced === '0' || introduced === null || compareVersions(current, introduced) >= 0) && compareVersions(current, e.fixed) < 0;
      if (inRange) return e.fixed;
      if (compareVersions(e.fixed, current) > 0) later.push(e.fixed);
    }
  }
  return later.sort(compareVersions)[0] ?? null;
}

const firstLine = (s) => (s ?? '').split('\n').find((l) => l.trim())?.slice(0, 160);
