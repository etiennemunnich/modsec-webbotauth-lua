// identifier.ts: Signature-Agent identifiers (WBA draft 5.5). The same rules
// as lua/wba/identifier.lua, which says why each one holds; both suites run
// every row of lua/tests/fixtures/identifiers.tsv.
//
//   directoryIdentifier(origin, strict)  type=directory: the well-known URI
//   urlIdentifier(value)                 type=jwks_uri / cimd: the member value,
//                                        normalized, query and fragment discarded
//   validIdentifier(id)                  id is its own normal form

export const WELL_KNOWN = "/.well-known/http-message-signatures-directory";

const lower = (s: string) => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));

function decOctet(s: string): number | null {
  if (!/^\d{1,3}$/.test(s) || (s.length > 1 && s[0] === "0")) return null;
  const n = Number(s);
  return n > 255 ? null : n;
}

function ipv4(s: string): number[] | null {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s);
  if (!m) return null;
  const o = m.slice(1).map(decOctet);
  return o.every((x) => x !== null) ? (o as number[]) : null;
}

function h16List(s: string): number[] | null {
  if (s === "") return [];
  const out: number[] = [];
  for (const part of s.split(":")) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
    out.push(parseInt(part, 16));
  }
  return out;
}

/** The eight 16-bit groups of an RFC 3986 IPv6address in lowercase, or null. */
function ipv6Groups(text: string): number[] | null {
  let s = text;
  if (s === "" || /[^0-9a-f:.]/.test(s)) return null;
  let tail: number[] = [];
  if (s.includes(".")) {
    const dotted = /:([0-9.]+)$/.exec(s)?.[1]; // ls32: an IPv4address ends it
    const o = dotted !== undefined ? ipv4(dotted) : null;
    if (!o || dotted === undefined) return null;
    tail = [o[0] * 256 + o[1], o[2] * 256 + o[3]];
    s = s.slice(0, s.length - dotted.length);
    if (!s.endsWith("::")) s = s.slice(0, -1);
  }
  let groups: number[];
  const a = s.indexOf("::");
  if (a >= 0) {
    if (s.indexOf("::", a + 2) >= 0) return null;
    const left = h16List(s.slice(0, a)), right = h16List(s.slice(a + 2));
    if (!left || !right) return null;
    const n = left.length + right.length + tail.length;
    if (n > 7) return null; // "::" stands for at least one group
    groups = [...left, ...Array(8 - n).fill(0), ...right];
  } else {
    const all = h16List(s);
    if (!all || all.length + tail.length !== 8) return null;
    groups = all;
  }
  return [...groups, ...tail];
}

const dotted = (hi: number, lo: number) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;

/** RFC 5952 4.1-4.3 and 5 (IPv4-mapped and IPv4-translated in dotted decimal). */
function ipv6Text(g: number[]): string {
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0) {
    if (g[4] === 0 && g[5] === 0xffff) return "::ffff:" + dotted(g[6], g[7]);
    if (g[4] === 0xffff && g[5] === 0) return "::ffff:0:" + dotted(g[6], g[7]);
  }
  let best = 0, len = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > len) { best = i; len = j - i; }
    i = j;
  }
  const hex = (from: number, to: number) => g.slice(from, to).map((x) => x.toString(16)).join(":");
  if (len < 2) return hex(0, 8);
  return hex(0, best) + "::" + hex(best + len, 8);
}

type Mode = "origin" | "lenient" | "url";

/**
 * Canonical host[:port], or null (modes as in identifier.lua). The host
 * grammars admit neither "@" (userinfo, RFC 9110 4.2.4) nor A-Z (RFC 6454
 * 6.2); only "url" mode lowercases first.
 */
function authority(input: string, mode: Mode): string | null {
  const a = mode === "url" ? lower(input) : input;
  let host: string;
  let port: string | undefined;
  if (a.startsWith("[")) {
    const m = /^\[([^\]]*)\](.*)$/.exec(a);
    const g = m ? ipv6Groups(m[1]) : null;
    if (!m || !g) return null;
    host = `[${ipv6Text(g)}]`;
    if (m[2] !== "") {
      const p = /^:(\d*)$/.exec(m[2]);
      if (!p) return null;
      port = p[1];
    }
  } else {
    const m = /^([^:]*):(\d*)$/.exec(a);
    host = m ? m[1] : a;
    if (m) port = m[2];
    if (!/^[a-z0-9][a-z0-9.-]*$/.test(host) || /[.-]$/.test(host)) return null;
  }
  if (port === "") {
    if (mode !== "url") return null;
    port = undefined;
  }
  if (port !== undefined) {
    if (!/^[1-9]\d{0,4}$/.test(port) || Number(port) > 65535) return null;
    if (port === "443") {
      if (mode === "origin") return null;
      port = undefined;
    }
  }
  return port !== undefined ? `${host}:${port}` : host;
}

/** The directory identifier for an https origin, or null. strict: a request's member (5.5). */
export function directoryIdentifier(origin: string, strict = false): string | null {
  const m = /^https:\/\/([^/?#]+)(.*)$/.exec(origin);
  if (!m || (m[2] !== "" && m[2] !== "/")) return null;
  const hostport = authority(m[1], strict ? "origin" : "lenient");
  return hostport === null ? null : `https://${hostport}${WELL_KNOWN}`;
}

const PCHAR = "A-Za-z0-9\\-._~!$&'()*+,;=:@%";
const PATH_BAD = new RegExp(`[^${PCHAR}/]`);
const QUERY_BAD = new RegExp(`[^${PCHAR}/?]`);
const pctOk = (s: string) => !s.replace(/%[0-9A-Fa-f]{2}/g, "").includes("%");
const pctNormal = (s: string) => s.replace(/%([0-9A-Fa-f]{2})/g, (_, h: string) => {
  const c = String.fromCharCode(parseInt(h, 16));
  return /^[A-Za-z0-9\-._~]$/.test(c) ? c : "%" + h.toUpperCase();
});

function removeDotSegments(path: string): string {
  const out: string[] = [];
  const segs = path.slice(1).split("/");
  for (const seg of segs) {
    if (seg === "..") out.pop();
    else if (seg !== ".") out.push(seg);
  }
  const last = segs[segs.length - 1];
  if (last === "." || last === "..") out.push("");
  return "/" + out.join("/");
}

/** The identifier of a jwks_uri or cimd member value, or null. */
export function urlIdentifier(value: string): string | null {
  if (/[^A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]/.test(value)) return null;
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):(.*)$/.exec(value);
  if (!m || lower(m[1]) !== "https") return null;
  const a = /^\/\/([^/?#]*)(.*)$/.exec(m[2]);
  const hostport = a ? authority(a[1], "url") : null;
  if (!a || hostport === null) return null;
  const tail = a[2];
  const path = /^[^?#]*/.exec(tail)![0];
  const suffix = tail.slice(path.length);
  if (PATH_BAD.test(path) || !pctOk(path)) return null;
  if (suffix !== "") { // validated, then discarded (5.5)
    const query = /^\?([^#]*)/.exec(suffix)?.[1] ?? "";
    const hash = suffix.indexOf("#");
    const fragment = hash >= 0 ? suffix.slice(hash + 1) : "";
    for (const part of [query, fragment]) if (QUERY_BAD.test(part) || !pctOk(part)) return null;
  }
  const p = pctNormal(path);
  return `https://${hostport}${p === "" ? "/" : removeDotSegments(p)}`;
}

/** True when id is an identifier: its own normal form, with no query or fragment. */
export const validIdentifier = (id: string) => urlIdentifier(id) === id;
