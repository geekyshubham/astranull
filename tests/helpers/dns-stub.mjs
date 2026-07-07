/**
 * Deterministic DNS resolver stub for portal revamp tests (docs/ux/17 §2).
 * Unit, contract, and integration suites inject this instead of live DNS.
 */

const DEFAULT_TXT = new Map();

export function resetDnsStub(records = {}) {
  DEFAULT_TXT.clear();
  for (const [name, values] of Object.entries(records)) {
    DEFAULT_TXT.set(normalizeName(name), Array.isArray(values) ? values : [values]);
  }
}

function normalizeName(name) {
  return String(name ?? '').trim().toLowerCase().replace(/\.$/, '');
}

/**
 * @param {Record<string, string | string[]>} [records]
 */
export function createDnsStub(records = {}) {
  const txt = new Map();
  for (const [name, values] of Object.entries(records)) {
    txt.set(normalizeName(name), Array.isArray(values) ? values : [values]);
  }

  return {
    records: txt,
    async resolveTxt(name, { delayMs = 0, timeoutMs = 4000 } = {}) {
      if (delayMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
      if (delayMs >= timeoutMs) {
        const err = new Error('DNS lookup timed out');
        err.code = 'ETIMEOUT';
        throw err;
      }
      const key = normalizeName(name);
      const values = txt.get(key) ?? DEFAULT_TXT.get(key) ?? [];
      return values.map((value) => [String(value)]);
    },
    setTxt(name, value) {
      txt.set(normalizeName(name), [String(value)]);
    },
    clear() {
      txt.clear();
    },
  };
}

export function dnsTimeoutResolver({ timeoutMs = 4000 } = {}) {
  return {
    async resolveTxt() {
      await new Promise((resolve) => setTimeout(resolve, timeoutMs + 50));
      const err = new Error('DNS lookup timed out');
      err.code = 'ETIMEOUT';
      throw err;
    },
  };
}