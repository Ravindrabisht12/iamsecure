// Minimal TOML subset parser for lockfiles and pyproject.toml: [tables], [[array tables]],
// dotted keys, strings, numbers, booleans, (multi-line) arrays and inline tables.

function parseValue(src, i) {
  const skipWs = () => {
    while (i < src.length) {
      if (/\s/.test(src[i])) i++;
      else if (src[i] === '#') while (i < src.length && src[i] !== '\n') i++;
      else break;
    }
  };
  skipWs();
  const ch = src[i];
  if (src.startsWith('"""', i) || src.startsWith("'''", i)) {
    const q = src.slice(i, i + 3);
    const end = src.indexOf(q, i + 3);
    return [src.slice(i + 3, end).replace(/^\n/, ''), end + 3];
  }
  if (ch === '"') {
    let j = i + 1;
    let out = '';
    while (j < src.length && src[j] !== '"') {
      if (src[j] === '\\') {
        const n = src[j + 1];
        out += { n: '\n', t: '\t', '"': '"', '\\': '\\' }[n] ?? n;
        j += 2;
      } else out += src[j++];
    }
    return [out, j + 1];
  }
  if (ch === "'") {
    const end = src.indexOf("'", i + 1);
    return [src.slice(i + 1, end), end + 1];
  }
  if (ch === '[') {
    const arr = [];
    i++;
    for (;;) {
      skipWs();
      if (src[i] === ']') return [arr, i + 1];
      const [v, next] = parseValue(src, i);
      arr.push(v);
      i = next;
      skipWs();
      if (src[i] === ',') i++;
    }
  }
  if (ch === '{') {
    const obj = {};
    i++;
    for (;;) {
      skipWs();
      if (src[i] === '}') return [obj, i + 1];
      const m = /^\s*("[^"]*"|'[^']*'|[\w.-]+)\s*=/.exec(src.slice(i, i + 200));
      if (!m) return [obj, src.indexOf('}', i) + 1];
      i += m[0].length;
      const [v, next] = parseValue(src, i);
      setPath(obj, splitKey(m[1]), v);
      i = next;
      skipWs();
      if (src[i] === ',') i++;
    }
  }
  const m = /^[^,\]}\n#]+/.exec(src.slice(i));
  const raw = (m?.[0] ?? '').trim();
  const v = raw === 'true' ? true : raw === 'false' ? false : /^-?\d+(\.\d+)?$/.test(raw) ? Number(raw) : raw;
  return [v, i + (m?.[0].length ?? 0)];
}

function splitKey(k) {
  const parts = [];
  for (const m of k.matchAll(/"([^"]*)"|'([^']*)'|([^.\s]+)/g)) parts.push(m[1] ?? m[2] ?? m[3]);
  return parts;
}

function setPath(obj, keys, value) {
  let o = obj;
  for (const k of keys.slice(0, -1)) {
    if (Array.isArray(o[k])) o = o[k].at(-1);
    else o = o[k] ??= {};
  }
  o[keys.at(-1)] = value;
}

export function parseToml(src) {
  const root = {};
  let current = root;
  let i = 0;
  while (i < src.length) {
    const rest = src.slice(i);
    const ws = /^\s+/.exec(rest);
    if (ws) {
      i += ws[0].length;
      continue;
    }
    if (rest[0] === '#') {
      i = src.indexOf('\n', i) === -1 ? src.length : src.indexOf('\n', i);
      continue;
    }
    const arrTable = /^\[\[\s*([^\]]+?)\s*\]\]/.exec(rest);
    if (arrTable) {
      const keys = splitKey(arrTable[1]);
      let o = root;
      for (const k of keys.slice(0, -1)) o = Array.isArray(o[k]) ? o[k].at(-1) : (o[k] ??= {});
      const last = keys.at(-1);
      if (!Array.isArray(o[last])) o[last] = [];
      current = {};
      o[last].push(current);
      i += arrTable[0].length;
      continue;
    }
    const table = /^\[\s*([^\]]+?)\s*\]/.exec(rest);
    if (table) {
      current = root;
      for (const k of splitKey(table[1])) current = Array.isArray(current[k]) ? current[k].at(-1) : (current[k] ??= {});
      i += table[0].length;
      continue;
    }
    const kv = /^("[^"]*"|'[^']*'|[\w.-]+)\s*=\s*/.exec(rest);
    if (!kv) {
      i = src.indexOf('\n', i) === -1 ? src.length : src.indexOf('\n', i) + 1;
      continue;
    }
    const [value, next] = parseValue(src, i + kv[0].length);
    setPath(current, splitKey(kv[1]), value);
    i = next;
  }
  return root;
}
