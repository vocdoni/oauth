// SPDX-License-Identifier: AGPL-3.0-only

const RETURN_TO_RE = /^\/[^/\\]/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\x00-\x1f\x7f]/;
const MAX_RETURN_TO = 2048;

/**
 * Keeps relative paths only: must match ^/[^/\\], hold no ASCII control
 * character (browsers strip tab/CR/LF, turning "/\t/evil" into "//evil") and
 * be at most 2048 bytes; anything else becomes "/".
 */
export function sanitizeReturnTo(s: string | null | undefined): string {
  if (!s || Buffer.byteLength(s, 'utf8') > MAX_RETURN_TO || !RETURN_TO_RE.test(s) || CONTROL_RE.test(s)) return '/';
  return s;
}

/** Lower-cases A-Z only, so both kits agree byte for byte. */
export function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}

/** Returns the lower-cased e-mail when verified claims pass the admission rules. */
export function admit(
  email: unknown,
  verified: unknown,
  domains: readonly string[],
  emails: readonly string[],
): string | null {
  if (typeof email !== 'string' || email === '' || verified !== true) return null;
  const e = asciiLower(email);
  if (emails.includes(e)) return e;
  const at = e.lastIndexOf('@');
  if (at <= 0 || at === e.length - 1) return null;
  return domains.includes(e.slice(at + 1)) ? e : null;
}

export function hasControl(s: string): boolean {
  return CONTROL_RE.test(s);
}
