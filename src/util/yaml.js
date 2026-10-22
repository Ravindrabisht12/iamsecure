// Minimal YAML subset parser — enough for pnpm-lock.yaml and yarn berry lockfiles:
// block mappings, block sequences of scalars, quoted/plain scalars. Flow collections
// ({...} / [...]) are kept as raw strings since lockfile parsing never needs them.

function unquote(s) {
  s = s.trim();
  if (s.length >= 2 && s[0] === '"' && s.at(-1) === '"') {
    try {
      return JSON.parse(s);
    } catch {
      return s.slice(1, -1);
    }
  }
  if (s.length >= 2 && s[0] === "'" && s.at(-1) === "'") return s.slice(1, -1).replace(/''/g, "'");
  return s;
}

/** Split "key: value" honoring a quoted key. Returns null when the line isn't a mapping entry. */
function splitKey(line) {
  if (line[0] === '"' || line[0] === "'") {
    const q = line[0];
    let i = 1;
    while (i < line.length) {
      if (line[i] === '\\' && q === '"') i += 2;
      else if (line[i] === q && q === "'" && line[i + 1] === q) i += 2;
      else if (line[i] === q) break;
      else i++;
    }
    const rest = line.slice(i + 1);
    if (!rest.startsWith(':')) return null;
    return [unquote(line.slice(0, i + 1)), rest.slice(1).trim()];
  }
  const m = line.match(/^(.*?):(?:\s+(.*))?$/);
  if (!m) return null;
  return [m[1].trim(), (m[2] ?? '').trim()];
}

function stripComment(v) {
  if (!v || v[0] === '"' || v[0] === "'") return v;
  const i = v.indexOf(' #');
  return i === -1 ? v : v.slice(0, i).trim();
}

export function parseYaml(text) {
  const root = {};
  // Each frame: indent of the line that opened it, the container, and where it lives.
  const stack = [{ indent: -1, obj: root, owner: null, key: null }];

  for (const raw of text.split(/\r?\n/)) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed === '---') continue;
    const indent = raw.length - raw.trimStart().length;
    const isItem = trimmed === '-' || trimmed.startsWith('- ');

    // A sequence may sit at the same indent as its key ("key:\n- a").
    const top = stack.at(-1);
    const sameIndentList = isItem && top.indent === indent && top.owner && isEmptyContainer(top.obj);
    if (!sameIndentList) while (stack.length > 1 && indent <= stack.at(-1).indent) stack.pop();

    const frame = stack.at(-1);
    if (isItem) {
      if (!Array.isArray(frame.obj)) {
        if (!frame.owner || !isEmptyContainer(frame.obj)) continue;
        frame.obj = frame.owner[frame.key] = [];
      }
      frame.obj.push(unquote(stripComment(trimmed.slice(1).trim())));
      continue;
    }

    const kv = splitKey(trimmed);
    if (!kv || Array.isArray(frame.obj)) continue;
    const [key, value] = kv;
    if (value === '') {
      frame.obj[key] = {};
      stack.push({ indent, obj: frame.obj[key], owner: frame.obj, key });
    } else {
      frame.obj[key] = unquote(stripComment(value));
    }
  }
  return root;
}

function isEmptyContainer(o) {
  return (Array.isArray(o) && o.length === 0) || (o && typeof o === 'object' && Object.keys(o).length === 0);
}
