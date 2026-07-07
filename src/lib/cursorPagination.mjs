/**
 * Opaque cursor helpers for portal revamp list endpoints.
 */

export function encodeCursor(payload) {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

export function decodeCursor(cursor) {
  if (!cursor) return null;
  try {
    const parsed = JSON.parse(Buffer.from(String(cursor), 'base64url').toString('utf8'));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch {
    return null;
  }
}

/**
 * @template T
 * @param {T[]} items
 * @param {{ limit?: number, cursor?: string | null, cursorField?: string }} options
 */
export function paginateItems(items, options = {}) {
  const limit = Math.max(1, Math.min(Number(options.limit) || 50, 100));
  const cursorField = options.cursorField ?? 'id';
  const decoded = decodeCursor(options.cursor);
  let startIndex = 0;
  if (decoded && decoded[cursorField] != null) {
    const idx = items.findIndex((item) => item[cursorField] === decoded[cursorField]);
    startIndex = idx >= 0 ? idx + 1 : 0;
  }
  const page = items.slice(startIndex, startIndex + limit);
  const last = page[page.length - 1];
  const next_cursor =
    startIndex + limit < items.length && last
      ? encodeCursor({ [cursorField]: last[cursorField] })
      : null;
  return { items: page, next_cursor, count: page.length };
}