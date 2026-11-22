// Shared helpers for the app-key system. This file has NO onRequest export, so Pages
// does not turn it into a route. New endpoints import from here.
//
// KV layout
//   data            -> site data (events, polls, files, votes)           [existing]
//   akey:<sha256>   -> { label, createdAt, expiresAt, revoked, deviceId, boundAt, lastSeenAt }
//                      (the same record is also stored as KV *metadata* so the admin list
//                       needs one KV.list call instead of hundreds of gets)
//   rl:<ip>         -> failed-attempt counter, expirationTtl 900
//
// Plaintext keys are never stored or logged. The id of a key is the SHA-256 hex of its
// normalized form.

export const J = (o, s = 200) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

export const FAIL = (error, status) => J({ ok: false, error }, status);

// ---- edit-key check (constant time, same as the original) -------------------------
export function okKey(env, k) {
  const e = env.EDIT_KEY || "";
  if (!e || typeof k !== "string" || k.length !== e.length) return false;
  let d = 0;
  for (let i = 0; i < e.length; i++) d |= k.charCodeAt(i) ^ e.charCodeAt(i);
  return d === 0;
}

// ---- app keys ---------------------------------------------------------------------
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32 (no I L O U)
export const KEY_RE = /^[0-9A-HJKMNP-TV-Z]{16}$/;

// uppercase, strip non-alphanumerics, O->0, I/L->1
export function normalizeKey(s) {
  return String(s ?? "")
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
}

export const isValidKey = (norm) => KEY_RE.test(norm);

export async function hashKey(norm) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(norm));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// 16 chars, 5 bits each from crypto.getRandomValues (256 % 32 === 0, so no modulo bias)
export function genKey() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let s = "";
  for (const b of bytes) s += ALPHABET[b & 31];
  return s.replace(/(.{4})(?=.)/g, "$1-");
}

// ---- failed-attempt limiter (per IP) ----------------------------------------------
// KV is eventually consistent and read-modify-write is not atomic, so this is approximate.
// Back it up with a Cloudflare WAF rate-limiting rule on /api/* (see README).
export const RL_MAX = 10;
export const RL_TTL = 900;

export const clientIp = (request) => request.headers.get("cf-connecting-ip") || "unknown";

export async function rlGet(env, ip) {
  return parseInt(await env.KV.get("rl:" + ip), 10) || 0;
}
export const rlBlocked = (n) => n >= RL_MAX;
// n = count returned by rlGet (saves a KV read)
export async function rlFail(env, ip, n) {
  await env.KV.put("rl:" + ip, String(n + 1), { expirationTtl: RL_TTL });
}

// ---- key records ------------------------------------------------------------------
const HOUR = 3600000;
const DEVICE_RE = /^[A-Za-z0-9-]{16,80}$/;

export async function putRec(env, id, rec) {
  // metadata copy powers the cheap admin list (limit 1024 bytes; records are ~300)
  await env.KV.put("akey:" + id, JSON.stringify(rec), { metadata: rec });
}

export const isExpired = (rec, now) => !!rec.expiresAt && now >= rec.expiresAt;

// ---- app endpoints ----------------------------------------------------------------
// mode: "activate" | "check" | "release" | "notes"
export async function appHandler(request, env, mode, now = Date.now()) {
  const wantMethod = mode === "notes" ? "GET" : "POST";
  if (request.method !== wantMethod) return FAIL("method_not_allowed", 405);
  if (!env.KV) return FAIL("server_error", 500);

  const ip = clientIp(request);
  const fails = await rlGet(env, ip);
  if (rlBlocked(fails)) return FAIL("rate_limited", 429);

  const device = request.headers.get("x-device-id") || "";
  if (!DEVICE_RE.test(device)) return FAIL("bad_device", 400);

  const norm = normalizeKey(request.headers.get("x-app-key"));
  let id = null;
  let rec = null;
  if (isValidKey(norm)) {
    id = await hashKey(norm);
    rec = await env.KV.get("akey:" + id, "json");
  }
  if (!rec) {
    await rlFail(env, ip, fails);
    return FAIL("invalid_key", 403);
  }

  // releasing is always allowed so a user can clean up a revoked/expired key
  if (mode === "release") {
    let released = false;
    if (rec.deviceId === device) {
      rec.deviceId = null;
      rec.boundAt = null;
      await putRec(env, id, rec);
      released = true;
    }
    return J({ ok: true, released });
  }

  if (rec.revoked) return FAIL("revoked", 403);
  if (isExpired(rec, now)) return FAIL("expired", 403);

  const touch = () => !rec.lastSeenAt || now - rec.lastSeenAt >= HOUR;

  if (mode === "activate") {
    if (!rec.deviceId) {
      // not atomic: two simultaneous first activations can both succeed (accepted)
      rec.deviceId = device;
      rec.boundAt = now;
      rec.lastSeenAt = now;
      await putRec(env, id, rec);
    } else if (rec.deviceId !== device) {
      return FAIL("key_in_use", 403);
    } else if (touch()) {
      rec.lastSeenAt = now;
      await putRec(env, id, rec);
    }
    return J({ ok: true, bound: true, expiresAt: rec.expiresAt ?? null });
  }

  // check + notes: a key bound to another device is refused; an unbound key passes
  if (rec.deviceId && rec.deviceId !== device) return FAIL("key_in_use", 403);

  if (mode === "check") {
    if (touch()) {
      rec.lastSeenAt = now;
      await putRec(env, id, rec);
    }
    return J({ ok: true, bound: rec.deviceId === device, expiresAt: rec.expiresAt ?? null });
  }

  // notes
  const data = (await env.KV.get("data", "json")) || {};
  const notes = (Array.isArray(data.files) ? data.files : []).map((f) => {
    const n = { name: f.name, addedAt: Number.isFinite(f.addedAt) ? f.addedAt : 0 };
    if (f.id) {
      n.id = f.id;
      if (Number.isFinite(f.size)) n.size = f.size;
    } else if (f.url) n.url = f.url;
    return n;
  });
  return J({ ok: true, notes });
}
