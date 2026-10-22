/**
 * Blank out comments while keeping strings, line numbers and column positions intact,
 * so rules never fire on commented-out code.
 * @param {string} text
 * @param {'js'|'php'|'py'} lang
 * @param {{blankStrings?: boolean}} [opts] also blank the contents of string literals (quotes are kept)
 */
export function stripComments(text, lang = 'js', { blankStrings = false } = {}) {
  const out = text.split('');
  const blank = (from, to) => {
    for (let k = from; k < to; k++) if (out[k] !== '\n') out[k] = ' ';
  };
  const lineComment = lang === 'py' ? ['#'] : lang === 'php' ? ['//', '#'] : ['//'];
  const quotes = lang === 'js' ? '\'"`' : '\'"';
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (quotes.includes(ch)) {
      // Python triple-quoted strings.
      const triple = lang === 'py' && text.startsWith(ch.repeat(3), i);
      const end = triple ? ch.repeat(3) : ch;
      let j = i + end.length;
      while (j < text.length && !text.startsWith(end, j)) {
        if (text[j] === '\\') j++;
        else if (!triple && ch !== '`' && text[j] === '\n') break;
        j++;
      }
      if (blankStrings) blank(i + end.length, Math.min(j, text.length));
      i = j + end.length;
      continue;
    }
    if (lang !== 'py' && text.startsWith('/*', i)) {
      const j = text.indexOf('*/', i + 2);
      const stop = j === -1 ? text.length : j + 2;
      blank(i, stop);
      i = stop;
      continue;
    }
    const lc = lineComment.find((c) => text.startsWith(c, i));
    // `//` right after ':' is a URL, not a comment (http://…).
    if (lc && !(lc === '//' && text[i - 1] === ':')) {
      const j = text.indexOf('\n', i);
      const stop = j === -1 ? text.length : j;
      blank(i, stop);
      i = stop;
      continue;
    }
    i++;
  }
  return out.join('');
}
