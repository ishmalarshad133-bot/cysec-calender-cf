// Minimal in-memory stand-in for a Workers KV namespace (get/put/delete/list + TTL + metadata).
export class FakeKV {
  constructor() { this.m = new Map(); this.now = () => Date.now(); }
  _live(k) {
    const e = this.m.get(k);
    if (!e) return null;
    if (e.exp && this.now() >= e.exp) { this.m.delete(k); return null; }
    return e;
  }
  async get(k, type) {
    const e = this._live(k);
    if (!e) return null;
    return type === "json" ? JSON.parse(e.v) : e.v;
  }
  async put(k, v, opts = {}) {
    this.m.set(k, {
      v: typeof v === "string" ? v : String(v),
      exp: opts.expirationTtl ? this.now() + opts.expirationTtl * 1000 : 0,
      meta: opts.metadata === undefined ? undefined : JSON.parse(JSON.stringify(opts.metadata)),
      ttl: opts.expirationTtl,
    });
  }
  async delete(k) { this.m.delete(k); }
  async list({ prefix = "" } = {}) {
    const keys = [];
    for (const k of [...this.m.keys()].sort()) {
      if (!k.startsWith(prefix)) continue;
      const e = this._live(k);
      if (e) keys.push({ name: k, metadata: e.meta });
    }
    return { keys, list_complete: true };
  }
}
