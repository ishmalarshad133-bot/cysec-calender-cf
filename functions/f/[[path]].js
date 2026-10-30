// /f/<id>/<name>.pdf -> opens the PDF in the browser; add ?dl=1 to force a download
export async function onRequest({ request, env }) {
  if (!env.KV) return new Response("KV binding missing", { status: 500 });
  const u = new URL(request.url);
  const id = u.pathname.split("/")[2] || "";
  if (!/^[a-f0-9]{16}$/.test(id)) return new Response("Not found", { status: 404 });
  const r = await env.KV.getWithMetadata("file:" + id, { type: "arrayBuffer" });
  if (!r || !r.value) return new Response("Not found", { status: 404 });
  const name = r.metadata?.name || "file.pdf";
  const dl = u.searchParams.has("dl");
  return new Response(r.value, {
    headers: {
      "content-type": "application/pdf",
      "content-disposition": `${dl ? "attachment" : "inline"}; filename*=UTF-8''${encodeURIComponent(name)}`,
      "x-content-type-options": "nosniff",
      "cache-control": "public, max-age=300",
    },
  });
}
