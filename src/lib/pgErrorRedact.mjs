const PG_URL_RE = /postgres(?:ql)?:\/\/[^\s'"]+/gi;

/**
 * @param {unknown} message
 * @param {NodeJS.ProcessEnv | Record<string, string | undefined>} [env]
 */
export function redactDatabaseUrlInMessage(message, env = process.env) {
  let text = message instanceof Error ? message.message : String(message ?? '');
  text = text.replace(PG_URL_RE, '[redacted-database-url]');
  const url = String(env.ASTRANULL_DATABASE_URL ?? '').trim();
  if (url && text.includes(url)) {
    text = text.split(url).join('[redacted-database-url]');
  }
  return text;
}