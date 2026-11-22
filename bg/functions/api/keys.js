// POST /api/keys  (header x-edit-key)  body { action, ... }
//   list | create {label,count,expiresAt} | revoke {id} | unrevoke {id} | unbind {id} | delete {id}
// Plaintext keys are returned ONCE by create and never by list.
import { J, FAIL, okKey, genKey, normalizeKey, hashKey, putRec, clientIp, rlGet, rlBlocked, rlFail } from "../_lib/common.js";

const MAX_KEYS = 500;
const ID_RE = /^[a-f0-9]{64}$/;

async function listAll(env) {
  const out = [];
  let cursor;
  for (let i = 0; i < 5; i++) {
    const r = await env.KV.list({ prefix: "akey:", cursor });
    for (const k of r.keys) {
      let rec = k.metadata;
      if (!rec) rec = await env.KV.get(k.name, "json"); // fallback, should not happen
      if (rec) out.push({ id: k.name.slice(5), rec });
    }
    if (r.list_complete) break;
    cursor = r.cursor;
  }
  return out;
}

export async function onRequest({ request, env }) {
  if (request.method !== "POST") return FAIL("method_not_allowed", 405);
  if (!env.KV) return FAIL("server_error", 500);

  const ip = clientIp(request);
  const fails = await rlGet(env, ip);
  if (rlBlocked(fails)) return FAIL("rate_limited", 429);
  if (!okKey(env, request.headers.get("x-edit-key"))) {
    await rlFail(env, ip, fails);
    return FAIL("invalid_key", 403);
  }

  let b;
  try { b = await request.json(); } catch { return FAIL("bad_request", 400); }
  if (!b || typeof b !== "object") return FAIL("bad_request", 400);
  const now = Date.now();

  if (b.action === "list") {
    const keys = (await listAll(env))
      .map(({ id, rec }) => ({
        id,
        label: rec.label || "",
        createdAt: rec.createdAt || 0,
        expiresAt: rec.expiresAt ?? null,
        revoked: !!rec.revoked,
        deviceBound: !!rec.deviceId,
        boundAt: rec.boundAt ?? null,
        lastSeenAt: rec.lastSeenAt ?? null,
      }))
      .sort((a, c) => c.createdAt - a.createdAt);
    return J({ ok: true, keys });
  }

  if (b.action === "create") {
    const label = String(b.label ?? "").trim().slice(0, 60);
    const count = b.count;
    if (!Number.isInteger(count) || count < 1 || count > 50) return FAIL("bad_request", 400);
    let expiresAt = null;
    if (b.expiresAt !== null && b.expiresAt !== undefined) {
      if (typeof b.expiresAt !== "number" || !Number.isFinite(b.expiresAt) || b.expiresAt <= now) return FAIL("bad_request", 400);
      expiresAt = Math.floor(b.expiresAt);
    }
    const existing = (await listAll(env)).length;
    if (existing + count > MAX_KEYS) return FAIL("limit_reached", 400);

    const made = [];
    for (let i = 0; i < count; i++) {
      const key = genKey();
      const id = await hashKey(normalizeKey(key));
      await putRec(env, id, { label, createdAt: now, expiresAt, revoked: false, deviceId: null, boundAt: null, lastSeenAt: null });
      made.push({ id, key });
    }
    return J({ ok: true, keys: made });
  }

  if (["revoke", "unrevoke", "unbind", "delete"].includes(b.action)) {
    if (typeof b.id !== "string" || !ID_RE.test(b.id)) return FAIL("bad_request", 400);
    const rec = await env.KV.get("akey:" + b.id, "json");
    if (!rec) return FAIL("not_found", 404);
    if (b.action === "delete") {
      await env.KV.delete("akey:" + b.id);
    } else {
      if (b.action === "revoke") rec.revoked = true;
      if (b.action === "unrevoke") rec.revoked = false;
      if (b.action === "unbind") { rec.deviceId = null; rec.boundAt = null; }
      await putRec(env, b.id, rec);
    }
    return J({ ok: true });
  }

  return FAIL("bad_request", 400);
}
