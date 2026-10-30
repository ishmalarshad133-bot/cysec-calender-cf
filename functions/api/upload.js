// /api/upload -> editors upload a PDF (raw bytes in the body)
const J = (o, s = 200) =>
  new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", "cache-control": "no-store" } });

function okKey(env, k) {
  const e = env.EDIT_KEY || "";
  if (!e || typeof k !== "string" || k.length !== e.length) return false;
  let d = 0;
  for (let i = 0; i < e.length; i++) d |= k.charCodeAt(i) ^ e.charCodeAt(i);
  return d === 0;
}

export async function onRequest({ request, env }) {
  if (!env.KV) return J({ error: "KV binding named KV is missing" }, 500);
  if (request.method !== "POST") return J({ error: "method not allowed" }, 405);
  if (!okKey(env, request.headers.get("x-edit-key"))) return J({ error: "only editors can upload" }, 403);
  const buf = await request.arrayBuffer();
  if (buf.byteLength > 5 * 1024 * 1024) return J({ error: "PDF is over 5 MB" }, 413);
  if (buf.byteLength < 5 || new TextDecoder().decode(buf.slice(0, 5)) !== "%PDF-") return J({ error: "only PDF files" }, 400);
  let name = "file.pdf";
  try { name = decodeURIComponent(request.headers.get("x-filename") || name); } catch {}
  name = name.replace(/[^\w.\- ()]/g, "_").slice(0, 80);
  if (!/\.pdf$/i.test(name)) name += ".pdf";
  const id = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
  await env.KV.put("file:" + id, buf, { metadata: { name } });
  return J({ ok: true, file: { id, name } });
}
