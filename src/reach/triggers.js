// Feature-level reachability for packages that are loaded but only dangerous when you use one feature.
// axios always loads form-data on Node, yet form-data's bugs only matter when you send multipart bodies.
//
// Each entry: the vulnerable package, a description of the feature, and a pattern that shows YOUR code
// uses it. No match → the package is loaded but the vulnerable path is never exercised (weak-to-moderate
// evidence: the pattern can miss indirect uses, so the score is reduced, not zeroed).

export const TRIGGERS = {
  'form-data': {
    feature: 'multipart/form-data request bodies',
    re: /\bnew\s+FormData\s*\(|multipart\/form-data|\.\s*(?:postForm|putForm|patchForm|toFormData)\s*\(|\bformSerializer\b/,
  },
  'proxy-addr': { feature: 'trust-proxy client IP resolution', re: /['"]trust proxy['"]|\btrustProxy\s*:/ },
  'tough-cookie': { feature: 'cookie jars', re: /\bCookieJar\b|\bjar\s*:/ },
};

/**
 * Does any runtime source file use the feature that makes `pkg`'s advisories exploitable?
 * @returns {null | {used: boolean, feature: string, where?: string}} null when no trigger is known.
 */
export function featureUse(pkg, src) {
  const t = TRIGGERS[pkg];
  if (!t || !src) return null;
  for (const f of src.files) {
    if (f.kind !== 'code' || f.context === 'build') continue;
    const text = src.texts.get(f.rel);
    const m = text && t.re.exec(text);
    if (m) return { used: true, feature: t.feature, where: `${f.rel}:${text.slice(0, m.index).split('\n').length}` };
  }
  return { used: false, feature: t.feature };
}
