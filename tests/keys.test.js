import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { FakeKV } from "./fake-kv.js";
import {
  normalizeKey, hashKey, genKey, isValidKey, appHandler, putRec, rlGet, rlFail, RL_MAX, okKey,
} from "../functions/_lib/common.js";
import { onRequest as keysApi } from "../functions/api/keys.js";
import { onRequest as mainApi } from "../functions/api/index.js";
import { onRequest as uploadApi } from "../functions/api/upload.js";

const DEV_A = "device-aaaaaaaaaaaaaaaa";
const DEV_B = "device-bbbbbbbbbbbbbbbb";
const DAY = 86400000;

const mkEnv = () => ({ KV: new FakeKV(), EDIT_KEY: "s3cret-edit-key" });
const req = (method, headers = {}, body) =>
  new Request("https://x.test/api", { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
const app = (env, mode, key, device, ip = "1.1.1.1", now) =>
  appHandler(
    req(mode === "notes" ? "GET" : "POST", { "x-app-key": key, "x-device-id": device ?? DEV_A, "cf-connecting-ip": ip }),
    env, mode, now,
  );
const body = async (r) => ({ status: r.status, cache: r.headers.get("cache-control"), ...(await r.json()) });

// create a key straight in KV; returns { key, id }
async function seed(env, over = {}) {
  const key = genKey();
  const id = await hashKey(normalizeKey(key));
  await putRec(env, id, { label: "t", createdAt: 1, expiresAt: null, revoked: false, deviceId: null, boundAt: null, lastSeenAt: null, ...over });
  return { key, id };
}

test("normalizeKey: case, separators, O/I/L mapping", () => {
  assert.equal(normalizeKey("abcd-efgh-jkmn-pqrs"), "ABCDEFGHJKMNPQRS");
  assert.equal(normalizeKey(" o0o0 iIlL 1234 5678 "), "0000111112345678");
  assert.equal(normalizeKey(null), "");
  assert.equal(normalizeKey("ab!@#cd"), "ABCD");
});

test("hashKey: sha-256 hex of the normalized key", async () => {
  const n = "0123456789ABCDEF";
  assert.equal(await hashKey(n), createHash("sha256").update(n).digest("hex"));
  assert.match(await hashKey(n), /^[a-f0-9]{64}$/);
});

test("genKey: format, alphabet, uniqueness, round-trips through normalize", () => {
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const k = genKey();
    assert.match(k, /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/);
    assert.ok(!/[ILOU]/.test(k));
    assert.equal(normalizeKey(k), k.replaceAll("-", ""));
    assert.ok(isValidKey(normalizeKey(k)));
    seen.add(k);
  }
  assert.equal(seen.size, 200);
});

test("activate: unbound -> binds; same device ok; other device key_in_use", async () => {
  const env = mkEnv();
  const { key, id } = await seed(env);
  let r = await body(await app(env, "activate", key, DEV_A));
  assert.equal(r.status, 200); assert.equal(r.ok, true); assert.equal(r.cache, "no-store");
  const rec = await env.KV.get("akey:" + id, "json");
  assert.equal(rec.deviceId, DEV_A); assert.ok(rec.boundAt > 0);
  r = await body(await app(env, "activate", key, DEV_A));
  assert.equal(r.status, 200);
  r = await body(await app(env, "activate", key, DEV_B));
  assert.deepEqual([r.status, r.ok, r.error], [403, false, "key_in_use"]);
  assert.equal((await env.KV.get("akey:" + id, "json")).deviceId, DEV_A); // unchanged
});

test("activate: lowercase / sloppy input works; garbage is invalid_key", async () => {
  const env = mkEnv();
  const { key } = await seed(env);
  assert.equal((await app(env, "activate", key.toLowerCase().replaceAll("-", " "), DEV_A)).status, 200);
  const r = await body(await app(env, "activate", "ZZZZ-ZZZZ-ZZZZ-ZZZZ", DEV_A));
  assert.deepEqual([r.status, r.error], [403, "invalid_key"]);
  const r2 = await body(await app(env, "activate", "short", DEV_A));
  assert.deepEqual([r2.status, r2.error], [403, "invalid_key"]);
});

test("revoked and expired keys are refused (403)", async () => {
  const env = mkEnv();
  const a = await seed(env, { revoked: true });
  const b = await seed(env, { expiresAt: 5000 });
  for (const mode of ["activate", "check", "notes"]) {
    let r = await body(await app(env, mode, a.key, DEV_A));
    assert.deepEqual([r.status, r.error], [403, "revoked"], mode);
    r = await body(await app(env, mode, b.key, DEV_A, "1.1.1.1", 5000));
    assert.deepEqual([r.status, r.error], [403, "expired"], mode);
  }
  // not yet expired
  assert.equal((await app(env, "activate", b.key, DEV_A, "1.1.1.1", 4999)).status, 200);
});

test("bad device id -> 400 bad_device (and does not count as a failed attempt)", async () => {
  const env = mkEnv();
  const { key } = await seed(env);
  for (const d of ["", "short", "has spaces aaaaaaaaaaaa", "x".repeat(81), "bad_underscore_aaaaaaa"]) {
    const r = await body(await app(env, "activate", key, d));
    assert.deepEqual([r.status, r.error], [400, "bad_device"], JSON.stringify(d));
  }
  assert.equal(await rlGet(env, "1.1.1.1"), 0);
});

test("check: does not bind; bound-to-other is refused; lastSeenAt updates at most daily", async () => {
  const env = mkEnv();
  const { key, id } = await seed(env);
  const T0 = 1_000_000_000_000;
  let r = await body(await app(env, "check", key, DEV_A, "1.1.1.1", T0));
  assert.deepEqual([r.status, r.ok, r.bound], [200, true, false]);
  assert.equal((await env.KV.get("akey:" + id, "json")).deviceId, null);

  await app(env, "activate", key, DEV_A, "1.1.1.1", T0);
  r = await body(await app(env, "check", key, DEV_A, "1.1.1.1", T0 + 60_000));
  assert.deepEqual([r.ok, r.bound], [true, true]);
  assert.equal((await env.KV.get("akey:" + id, "json")).lastSeenAt, T0); // < 24h: untouched
  await app(env, "check", key, DEV_A, "1.1.1.1", T0 + DAY);
  assert.equal((await env.KV.get("akey:" + id, "json")).lastSeenAt, T0 + DAY);

  r = await body(await app(env, "check", key, DEV_B, "1.1.1.1", T0 + 2 * DAY));
  assert.deepEqual([r.status, r.error], [403, "key_in_use"]);
});

test("release: unbinds own device, ignores other devices, then another device can activate", async () => {
  const env = mkEnv();
  const { key, id } = await seed(env);
  await app(env, "activate", key, DEV_A);
  let r = await body(await app(env, "release", key, DEV_B));
  assert.deepEqual([r.status, r.ok, r.released], [200, true, false]);
  assert.equal((await env.KV.get("akey:" + id, "json")).deviceId, DEV_A);
  r = await body(await app(env, "release", key, DEV_A));
  assert.deepEqual([r.ok, r.released], [true, true]);
  const rec = await env.KV.get("akey:" + id, "json");
  assert.equal(rec.deviceId, null); assert.equal(rec.boundAt, null);
  assert.equal((await app(env, "activate", key, DEV_B)).status, 200);
});

test("notes: maps data.files (pdf -> id, link -> url), addedAt ms epoch, size optional", async () => {
  const env = mkEnv();
  const { key } = await seed(env);
  await env.KV.put("data", JSON.stringify({ events: {}, polls: [], votes: {}, files: [
    { id: "0123456789abcdef", name: "a.pdf", addedAt: 1700000000000, size: 1234 },
    { name: "Drive", url: "https://drive.google.com/x", addedAt: 1700000001000 },
    { id: "fedcba9876543210", name: "old.pdf" },
  ] }));
  const r = await body(await app(env, "notes", key, DEV_A));
  assert.equal(r.status, 200); assert.equal(r.cache, "no-store");
  assert.deepEqual(r.notes[0], { name: "a.pdf", addedAt: 1700000000000, id: "0123456789abcdef", size: 1234 });
  assert.deepEqual(r.notes[1], { name: "Drive", addedAt: 1700000001000, url: "https://drive.google.com/x" });
  assert.equal(r.notes[2].addedAt, 0);
  assert.ok(!("url" in r.notes[0]) && !("id" in r.notes[1]));
  // empty site
  const env2 = mkEnv(); const s2 = await seed(env2);
  assert.deepEqual((await body(await app(env2, "notes", s2.key, DEV_A))).notes, []);
});

test("wrong HTTP method -> 405 JSON", async () => {
  const env = mkEnv();
  const r = await appHandler(req("GET", {}), env, "activate");
  assert.equal(r.status, 405);
  const r2 = await appHandler(req("POST", {}), env, "notes");
  assert.equal(r2.status, 405);
});

test("limiter: counts failures per IP, blocks at RL_MAX (60) with 429, TTL 900s, expires", async () => {
  const env = mkEnv();
  let t = 1_000_000;
  env.KV.now = () => t;
  for (let i = 0; i < RL_MAX; i++) {
    const r = await body(await app(env, "activate", "ZZZZ-ZZZZ-ZZZZ-ZZZZ", DEV_A, "9.9.9.9"));
    assert.equal(r.error, "invalid_key");
  }
  assert.equal(env.KV.m.get("rl:9.9.9.9").ttl, 900);
  let r = await body(await app(env, "activate", "ZZZZ-ZZZZ-ZZZZ-ZZZZ", DEV_A, "9.9.9.9"));
  assert.deepEqual([r.status, r.error], [429, "rate_limited"]);
  // a valid key from the blocked IP is also refused; another IP is fine
  const { key } = await seed(env);
  r = await body(await app(env, "activate", key, DEV_A, "9.9.9.9"));
  assert.equal(r.status, 429);
  assert.equal((await app(env, "activate", key, DEV_A, "8.8.8.8")).status, 200);
  // after the TTL the IP is free again
  t += 901_000;
  assert.equal((await app(env, "check", key, DEV_A, "9.9.9.9")).status, 200);
});

test("limiter: valid-key refusals (revoked / key_in_use) do not count as failures", async () => {
  const env = mkEnv();
  const a = await seed(env, { revoked: true });
  const b = await seed(env, { deviceId: DEV_B, boundAt: 1 });
  for (let i = 0; i < 15; i++) {
    await app(env, "activate", a.key, DEV_A, "7.7.7.7");
    await app(env, "activate", b.key, DEV_A, "7.7.7.7");
  }
  assert.equal(await rlGet(env, "7.7.7.7"), 0);
});

test("okKey: constant-time compare semantics", () => {
  const env = { EDIT_KEY: "abc" };
  assert.ok(okKey(env, "abc"));
  assert.ok(!okKey(env, "abd")); assert.ok(!okKey(env, "ab")); assert.ok(!okKey(env, 5));
  assert.ok(!okKey({}, ""));
});

// ---------------- admin endpoint ----------------
const admin = (env, b, key = env.EDIT_KEY, ip = "2.2.2.2") =>
  keysApi({ env, request: req("POST", { "x-edit-key": key, "cf-connecting-ip": ip }, b) }).then(body);

test("keys admin: create returns plaintext once, list never does; full lifecycle", async () => {
  const env = mkEnv();
  const c = await admin(env, { action: "create", label: "Batch 1", count: 3, expiresAt: null });
  assert.equal(c.status, 200); assert.equal(c.keys.length, 3);
  for (const k of c.keys) {
    assert.match(k.key, /^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$/);
    assert.equal(k.id, await hashKey(normalizeKey(k.key)));
  }
  const l = await admin(env, { action: "list" });
  assert.equal(l.keys.length, 3);
  const dump = JSON.stringify(l) + JSON.stringify([...env.KV.m.entries()]);
  for (const k of c.keys) assert.ok(!dump.includes(k.key) && !dump.includes(normalizeKey(k.key)), "plaintext leaked");
  assert.deepEqual(Object.keys(l.keys[0]).sort(), ["boundAt", "createdAt", "deviceBound", "expiresAt", "id", "label", "lastSeenAt", "revoked"]);
  assert.equal(l.keys[0].label, "Batch 1");

  const { id, key } = c.keys[0];
  assert.equal((await app(env, "activate", key, DEV_A)).status, 200);
  assert.equal((await admin(env, { action: "list" })).keys.find((k) => k.id === id).deviceBound, true);

  assert.equal((await admin(env, { action: "revoke", id })).ok, true);
  assert.equal((await body(await app(env, "check", key, DEV_A))).error, "revoked");
  assert.equal((await admin(env, { action: "unrevoke", id })).ok, true);
  assert.equal((await app(env, "check", key, DEV_A)).status, 200);

  assert.equal((await admin(env, { action: "unbind", id })).ok, true);
  assert.equal((await app(env, "activate", key, DEV_B)).status, 200);

  assert.equal((await admin(env, { action: "delete", id })).ok, true);
  assert.equal((await body(await app(env, "check", key, DEV_B))).error, "invalid_key");
  assert.equal((await admin(env, { action: "list" })).keys.length, 2);
});

test("keys admin: validation, cap of 500, wrong edit key, rate limit", async () => {
  const env = mkEnv();
  for (const bad of [{ count: 0 }, { count: 51 }, { count: 1.5 }, { count: "2" }, { count: 1, expiresAt: 5 }, { count: 1, expiresAt: "tomorrow" }]) {
    const r = await admin(env, { action: "create", label: "x", ...bad });
    assert.deepEqual([r.status, r.ok, r.error], [400, false, "bad_request"], JSON.stringify(bad));
  }
  const r = await admin(env, { action: "create", label: "x".repeat(100), count: 1, expiresAt: Date.now() + 1e9 });
  assert.equal(r.status, 200);
  assert.equal((await admin(env, { action: "list" })).keys[0].label.length, 60);
  assert.equal((await admin(env, { action: "revoke", id: "nothex" })).status, 400);
  assert.equal((await admin(env, { action: "revoke", id: "a".repeat(64) })).status, 404);
  assert.equal((await admin(env, { action: "nope" })).status, 400);

  // cap
  const env2 = mkEnv();
  for (let i = 0; i < 499; i++) await env2.KV.put("akey:" + String(i).padStart(64, "0"), "{}", { metadata: { label: "", createdAt: i } });
  assert.equal((await admin(env2, { action: "create", label: "", count: 1, expiresAt: null })).status, 200);
  const over = await admin(env2, { action: "create", label: "", count: 1, expiresAt: null });
  assert.deepEqual([over.status, over.error], [400, "limit_reached"]);

  // wrong edit key -> 403, then blocked after RL_MAX
  const env3 = mkEnv();
  for (let i = 0; i < RL_MAX; i++) assert.equal((await admin(env3, { action: "list" }, "wrong", "3.3.3.3")).status, 403);
  const blocked = await admin(env3, { action: "list" }, "wrong", "3.3.3.3");
  assert.deepEqual([blocked.status, blocked.error], [429, "rate_limited"]);
  assert.equal((await admin(env3, { action: "list" }, env3.EDIT_KEY, "3.3.3.3")).status, 429);
});

// ---------------- existing endpoints ----------------
const main = (env, b, ip = "4.4.4.4") => mainApi({ env, request: req("POST", { "cf-connecting-ip": ip }, b) }).then(body);

test("index.js save: stamps addedAt server-side, keeps it, keeps size, ignores client addedAt; old data ok", async () => {
  const env = mkEnv();
  await env.KV.put("data", JSON.stringify({ events: {}, polls: [], votes: {}, files: [{ id: "0123456789abcdef", name: "old.pdf" }] }));
  const K = env.EDIT_KEY;
  const t0 = Date.now();
  let r = await main(env, { action: "save", key: K, events: {}, polls: [], files: [
    { id: "0123456789abcdef", name: "old.pdf", addedAt: 1 },
    { id: "aaaaaaaaaaaaaaaa", name: "new.pdf", size: 4096, addedAt: 5 },
    { name: "L", url: "https://example.com/x" },
    { id: "bbbbbbbbbbbbbbbb", name: "huge.pdf", size: 99999999 },
  ] });
  assert.equal(r.ok, true);
  let f = (await env.KV.get("data", "json")).files;
  assert.ok(f[0].addedAt >= t0 && f[0].addedAt !== 1);          // legacy entry stamped now, client value ignored
  assert.equal(f[1].size, 4096); assert.ok(f[1].addedAt >= t0 && f[1].addedAt !== 5);
  assert.ok(f[2].addedAt >= t0 && !("size" in f[2]));
  assert.ok(!("size" in f[3]));                                  // over 5 MB ignored
  const stamped = f.map((x) => x.addedAt);
  await new Promise((res) => setTimeout(res, 5));
  await main(env, { action: "save", key: K, events: {}, polls: [], files: f.slice(0, 3) });
  f = (await env.KV.get("data", "json")).files;
  assert.deepEqual(f.map((x) => x.addedAt), stamped.slice(0, 3));   // kept
  assert.equal(f[1].size, 4096);
});

test("index.js: auth/save wrong key rate limited; auth contract unchanged", async () => {
  const env = mkEnv();
  assert.deepEqual(await main(env, { action: "auth", key: env.EDIT_KEY }, "5.5.5.5"), { status: 200, cache: "no-store", ok: true });
  assert.equal((await main(env, { action: "auth", key: "nope" }, "5.5.5.5")).ok, false);
  for (let i = 0; i < RL_MAX - 2; i++) await main(env, { action: "save", key: "nope" }, "5.5.5.5");
  assert.equal((await main(env, { action: "save", key: "nope" }, "5.5.5.5")).status, 403); // RL_MAX-th failure
  const r = await main(env, { action: "auth", key: env.EDIT_KEY }, "5.5.5.5");
  assert.deepEqual([r.status, r.error], [429, "rate_limited"]);
  // votes are not limited / not touched
  await env.KV.put("data", JSON.stringify({ events: {}, polls: [{ id: "p1", q: "q", opts: ["a", "b"] }], files: [], votes: {} }));
  assert.equal((await main(env, { action: "vote", voter: "voter-12345678", name: "n", pollId: "p1", option: "a" }, "5.5.5.5")).ok, true);
});

test("upload.js: returns size, limiter on wrong edit key", async () => {
  const env = mkEnv();
  const pdf = new TextEncoder().encode("%PDF-1.4 hello");
  const up = (key, ip) => uploadApi({ env, request: new Request("https://x.test/api/upload", { method: "POST", headers: { "x-edit-key": key, "x-filename": "n.pdf", "cf-connecting-ip": ip }, body: pdf }) }).then(body);
  const ok = await up(env.EDIT_KEY, "6.6.6.6");
  assert.equal(ok.ok, true); assert.equal(ok.file.size, pdf.byteLength); assert.match(ok.file.id, /^[a-f0-9]{16}$/);
  for (let i = 0; i < RL_MAX; i++) assert.equal((await up("bad", "6.6.6.6")).status, 403);
  assert.equal((await up(env.EDIT_KEY, "6.6.6.6")).status, 429);
});
