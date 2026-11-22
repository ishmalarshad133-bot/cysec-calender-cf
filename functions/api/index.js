// /api  -> read (GET) and save/vote/auth (POST). Data lives in one KV key: "data".
import { clientIp, rlGet, rlBlocked, rlFail } from "../_lib/common.js";

const J = (o, s = 200) =>
  new Response(JSON.stringify(o), {
    status: s,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

function okKey(env, k) {
  const e = env.EDIT_KEY || "";
  if (!e || typeof k !== "string" || k.length !== e.length) return false;
  let d = 0;
  for (let i = 0; i < e.length; i++) d |= k.charCodeAt(i) ^ e.charCodeAt(i);
  return d === 0;
}

export async function onRequest({ request, env }) {
  if (!env.KV) return J({ error: "KV binding named KV is missing" }, 500);
  const data = (await env.KV.get("data", "json")) || {};
  data.events = data.events || {};
  data.polls = data.polls || [];
  data.files = data.files || [];
  data.votes = data.votes || {};

  if (request.method === "GET") return J(data);
  if (request.method !== "POST") return J({ error: "method not allowed" }, 405);

  let b;
  try { b = await request.json(); } catch { return J({ error: "bad request" }, 400); }

  // failed edit-key attempts are rate limited per IP (approximate, see README)
  if (b.action === "auth" || b.action === "save") {
    const ip = clientIp(request);
    const fails = await rlGet(env, ip);
    if (rlBlocked(fails)) return J({ error: "rate_limited" }, 429);
    if (!okKey(env, b.key)) {
      await rlFail(env, ip, fails);
      return b.action === "auth" ? J({ ok: false }) : J({ error: "wrong edit key" }, 403);
    }
    if (b.action === "auth") return J({ ok: true });
  }

  // editors only
  if (b.action === "save") {
    const events = b.events && typeof b.events === "object" ? b.events : {};
    const polls = Array.isArray(b.polls) ? b.polls.slice(0, 30) : [];
    // addedAt is stamped by the server (kept from the previous save, never trusted from the client)
    const prev = new Map(data.files.map((f) => [f.id ? "id:" + f.id : "url:" + f.url, f]));
    const now = Date.now();
    const files = Array.isArray(b.files)
      ? b.files
          .map((f) => {
            if (!f || typeof f.name !== "string") return null;
            const name = f.name.slice(0, 80);
            if (typeof f.id === "string" && /^[a-f0-9]{16}$/.test(f.id)) {
              const old = prev.get("id:" + f.id);
              const out = { id: f.id, name, addedAt: old?.addedAt || now };
              const size = Number.isFinite(f.size) && f.size >= 0 && f.size <= 5242880 ? Math.floor(f.size) : old?.size;
              if (Number.isFinite(size)) out.size = size;
              return out;
            }
            if (typeof f.url === "string" && f.url.length <= 2000 && /^https?:\/\//i.test(f.url)) {
              const old = prev.get("url:" + f.url);
              return { name, url: f.url, addedAt: old?.addedAt || now };
            }
            return null;
          })
          .filter(Boolean)
          .slice(0, 200)
      : [];
    if (JSON.stringify({ events, polls, files }).length > 400000) return J({ error: "too big" }, 413);

    // delete PDFs removed from the Files list (and not attached to any event)
    const keep = new Set([...files.map((f) => f.id), ...Object.values(events).flat().map((e) => e?.file?.id)]);
    for (const f of data.files) if (f.id && !keep.has(f.id)) await env.KV.delete("file:" + f.id);

    // drop votes for polls that no longer exist
    const ids = new Set(polls.map((p) => p.id));
    for (const v of Object.values(data.votes))
      for (const id of Object.keys(v.answers || {})) if (!ids.has(id)) delete v.answers[id];

    await env.KV.put("data", JSON.stringify({ events, polls, files, votes: data.votes }));
    return J({ ok: true });
  }

  // anyone: vote
  if (b.action === "vote") {
    const name = String(b.name || "").trim().slice(0, 30);
    const voter = String(b.voter || "");
    const poll = data.polls.find((p) => p.id === b.pollId);
    if (!name || voter.length < 8 || voter.length > 80) return J({ error: "name needed" }, 400);
    if (!poll || !poll.opts.includes(b.option)) return J({ error: "bad option" }, 400);
    if (!data.votes[voter] && Object.keys(data.votes).length > 2000) return J({ error: "too many voters" }, 429);
    data.votes[voter] = { name, answers: { ...(data.votes[voter]?.answers || {}), [poll.id]: b.option } };
    await env.KV.put("data", JSON.stringify(data));
    return J({ ok: true });
  }

  return J({ error: "unknown action" }, 400);
}
