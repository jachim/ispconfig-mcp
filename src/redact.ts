/**
 * Secret masking for everything the MCP server returns.
 *
 * ISPConfig get-calls return private material in plain text (sites_web_domain_get: ssl_key, ssl_request;
 * mail_domain_get: dkim_private; *_user_get: password hashes; client_get: password, ...). Tool responses go
 * straight into the model's context, so these fields are replaced with REDACTED before they leave the client.
 *
 * The reverse direction matters too: a model that echoes a fetched record back into an update would write
 * the placeholder over the real secret, so fields carrying REDACTED are dropped from outgoing params.
 */

export const REDACTED = "[REDACTED]";

const SECRET_KEYS = new Set([
  "ssl_key",
  "ssl_request",
  "dkim_private",
  "private_key",
]);

// password, database_password, stats_password, backup_password, remote_password, passwort, client_secret,
// api_token, session_secret, ...
const SECRET_PATTERN = /(passw|secret|token|private_?key|api_?key)/i;

export function isSecretKey(key: string): boolean {
  return SECRET_KEYS.has(key.toLowerCase()) || SECRET_PATTERN.test(key);
}

/** Deep copy of `value` with every non-empty secret field replaced by REDACTED. */
export function redactSecrets<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => redactSecrets(item)) as T;
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (isSecretKey(key) && item !== null && item !== "" && (typeof item === "string" || typeof item === "number")) {
        out[key] = REDACTED;
      } else {
        out[key] = redactSecrets(item);
      }
    }
    return out as T;
  }
  return value;
}

/** Deep copy of outgoing params without fields whose value is REDACTED (never write the placeholder). */
export function dropRedacted<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.filter((item) => item !== REDACTED).map((item) => dropRedacted(item)) as T;
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (item === REDACTED) continue;
      out[key] = dropRedacted(item);
    }
    return out as T;
  }
  return value;
}
