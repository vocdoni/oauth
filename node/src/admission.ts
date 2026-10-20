// SPDX-License-Identifier: AGPL-3.0-only

const RETURN_TO_RE = /^\/[^/\\]/;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\x00-\x1f\x7f]/;
// return_to must be printable ASCII: a Fetch Location header cannot hold
// characters above U+00FF, and browsers percent-encode anything else anyway.
const NOT_PRINTABLE_ASCII_RE = /[^\x20-\x7e]/;
const MAX_RETURN_TO = 2048;

/**
 * Keeps same-origin relative paths only; anything else becomes "/". The value
 * must:
 * - be at most 2048 bytes and hold only printable ASCII (browsers strip
 *   tab/CR/LF, turning "/\t/evil" into "//evil", and a Fetch Location header
 *   cannot hold characters above U+00FF);
 * - match ^/[^/\\] and hold no backslash anywhere (browsers read "\" as "/");
 * - have no "." or ".." segment in its path (before "?" or "#"), counting the
 *   percent-encoded forms browsers treat the same ("%2e", ".%2e", ...).
 *
 * The Go kit applies the same rules byte for byte.
 */
export function sanitizeReturnTo(s: string | null | undefined): string {
  if (
    !s ||
    Buffer.byteLength(s, 'utf8') > MAX_RETURN_TO ||
    !RETURN_TO_RE.test(s) ||
    NOT_PRINTABLE_ASCII_RE.test(s) ||
    s.includes('\\') ||
    hasDotSegment(s)
  ) {
    return '/';
  }
  return s;
}

/** True when the path of s (up to the first "?" or "#") has a "." or ".." segment, literal or %2e-encoded (any case). */
function hasDotSegment(s: string): boolean {
  const end = s.search(/[?#]/);
  const path = end < 0 ? s : s.slice(0, end);
  return path.split('/').some((seg) => {
    const d = asciiLower(seg).replaceAll('%2e', '.');
    return d === '.' || d === '..';
  });
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
