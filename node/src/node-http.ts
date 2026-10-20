// SPDX-License-Identifier: AGPL-3.0-only

import type { IncomingMessage, ServerResponse } from 'node:http';

/**
 * Builds a body-less Fetch Request from a node:http / Express request. Only
 * the method, path, query and headers matter to the kit, so the origin is a
 * fixed placeholder; Express's originalUrl keeps the path absolute when the
 * middleware is mounted under a prefix.
 */
export function toRequest(req: IncomingMessage & { originalUrl?: string }): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) for (const v of value) headers.append(name, v);
    else headers.set(name, value);
  }
  const url = new URL(req.originalUrl ?? req.url ?? '/', 'http://vocauth.invalid');
  return new Request(url, { method: req.method ?? 'GET', headers });
}

/** Writes a Fetch Response (status, headers incl. every Set-Cookie, body) to a node:http response. */
export async function writeResponse(res: ServerResponse, r: Response): Promise<void> {
  res.statusCode = r.status;
  for (const [name, value] of r.headers) {
    if (name !== 'set-cookie') res.setHeader(name, value);
  }
  const cookies = r.headers.getSetCookie();
  if (cookies.length > 0) res.setHeader('Set-Cookie', cookies);
  res.end(r.body ? Buffer.from(await r.arrayBuffer()) : undefined);
}
