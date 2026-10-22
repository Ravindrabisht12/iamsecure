const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * fetch() + JSON with timeout and retry on 429/5xx/network errors.
 * @param {string} url
 * @param {{method?: string, body?: any, headers?: Record<string,string>, timeout?: number, retries?: number}} [opts]
 */
export async function fetchJson(url, { method = 'GET', body, headers = {}, timeout = 30000, retries = 2 } = {}) {
  for (let attempt = 0; ; attempt++) {
    let retryable = true;
    try {
      const res = await fetch(url, {
        method,
        body: body === undefined ? undefined : JSON.stringify(body),
        headers: { 'content-type': 'application/json', 'user-agent': 'iamsecure', ...headers },
        signal: AbortSignal.timeout(timeout),
      });
      if (!res.ok) {
        retryable = res.status === 429 || res.status >= 500;
        const text = await res.text().catch(() => '');
        throw new Error(`${method} ${url} → HTTP ${res.status} ${text.slice(0, 300)}`);
      }
      return await res.json();
    } catch (err) {
      if (!retryable || attempt >= retries) throw err;
      await sleep(600 * 2 ** attempt);
    }
  }
}

/** Run fn over items with at most `limit` in flight. Results keep input order. */
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}
