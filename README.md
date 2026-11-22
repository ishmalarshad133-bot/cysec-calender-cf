# CySec Academic Calendar (Cloudflare Pages)

Static site (`index.html`) plus Pages Functions in `functions/` and one KV namespace.

## Environment

| Name | Type | What |
|------|------|------|
| `KV` | KV namespace binding | holds site data (`data`), PDFs (`file:<id>`), app keys (`akey:<hash>`) and rate-limit counters (`rl:<ip>`) |
| `EDIT_KEY` | secret | editor password. Also the `x-edit-key` for `/api/keys` |

Set both under **Workers & Pages -> your project -> Settings -> Bindings / Variables and secrets**
(for both Production and Preview if you use previews). Redeploying does not change them.

## Endpoints

Existing: `GET /api`, `POST /api` (`auth`, `save`, `vote`), `POST /api/upload`, `GET /f/<id>/<name>.pdf`.

### App endpoints (for the Android app)

Headers on all: `x-app-key: XXXX-XXXX-XXXX-XXXX`, `x-device-id: <16-80 chars [A-Za-z0-9-]>`.
Responses are always JSON with `cache-control: no-store`. Success is HTTP 200 `{ ok:true, ... }`,
failure is `{ ok:false, error:<code> }`.

| Endpoint | Behaviour |
|----------|-----------|
| `POST /api/app/activate` | verify key. Unbound -> binds it to this device. Bound to this device -> ok. Bound to another device -> `key_in_use` |
| `POST /api/app/check` | same verify, never binds. Updates `lastSeenAt` at most once per hour. Returns `{ ok, bound, expiresAt }` |
| `POST /api/app/release` | if the key is bound to this device, unbind it. Returns `{ ok, released }`. Works even for revoked/expired keys |
| `GET /api/app/notes` | verify, then `{ ok:true, notes:[{ id?, name, url?, addedAt, size? }] }` built from the Files list (PDFs have `id`, links have `url`, `addedAt` is ms epoch) |

Error codes: `invalid_key` (403, also for unknown keys), `revoked` (403), `expired` (403),
`key_in_use` (403), `bad_device` (400), `rate_limited` (429). Extra codes outside the contract:
`method_not_allowed` (405), `server_error` (500, KV binding missing).

Notes on behaviour:
* `check` and `notes` accept an **unbound** key (the key is valid, it just has not been activated).
  `check` tells you via `bound:false`. A key bound to a different device is always refused.
* Entries in the Files list saved before this update have no `addedAt`; they are stamped with the
  time of the first save after the update. Until then `notes` reports `addedAt: 0` for them.

### Admin endpoint

`POST /api/keys` with header `x-edit-key: <EDIT_KEY>` and a JSON body:

* `{ action:"list" }` -> `{ ok, keys:[{ id, label, createdAt, expiresAt, revoked, deviceBound, boundAt, lastSeenAt }] }`
* `{ action:"create", label, count (1-50), expiresAt (ms epoch | null) }` -> `{ ok, keys:[{ id, key }] }`. **Plaintext keys are returned only here, once.**
* `{ action:"revoke"|"unrevoke"|"unbind"|"delete", id }`

A wrong edit key gives `403 invalid_key`. Other errors: `bad_request` (400), `not_found` (404),
`limit_reached` (400, more than 500 keys in total).

## How to create keys

1. Open the site, click **editor login**, enter the editor password.
2. In the **App keys** box enter a label, how many keys, and an optional expiry date, then **+ create**.
3. The new keys appear once in a text box. Press **Copy all** and store them somewhere safe.
   After you reload the page they cannot be shown again (only their hash is stored).
4. Per key you can **Revoke / Unrevoke**, **Unbind device** (lets the user activate on a new phone), or **Delete**.

Status meanings: `unused` = never activated, `active` = bound to a device, `revoked`, `expired`.

## Key storage and rules

* 16 characters of Crockford base32 from `crypto.getRandomValues`, shown as `XXXX-XXXX-XXXX-XXXX`.
  Input is normalized (uppercase, non-alphanumerics stripped, `O`->`0`, `I`/`L`->`1`).
* Only the SHA-256 hex of the normalized key is stored (`akey:<hash>`, the hash is also the key id).
* Max 500 keys.
* **Binding is not atomic** (KV has no compare-and-set). Two simultaneous first activations of the
  same key from different devices can both succeed. This is accepted.
* KV is eventually consistent: a revoke/unbind can take up to about a minute to reach every
  Cloudflare location. A `check` that rewrites a record at the same instant as an admin change
  could in theory overwrite it; the window is tiny and `check` only writes once per hour per key.

## Rate limiting

Failed attempts (unknown/invalid app key, wrong edit key on `/api/keys`, wrong edit key on `/api`
`auth`/`save`, and wrong edit key on `/api/upload`) are counted per IP (`cf-connecting-ip`) in KV key
`rl:<ip>` with a 900 s TTL. After 10 failures the IP gets `rate_limited` (429) until the counter expires.
Refusals for a *valid* key (`revoked`, `expired`, `key_in_use`) are not counted.

This limiter is **approximate** (KV is eventually consistent and read-modify-write is not atomic, so
a burst of parallel requests can slip through). Back it up with a Cloudflare WAF rate-limiting rule:

> Security -> WAF -> Rate limiting rules -> Create rule
> * If: URI Path **starts with** `/api/`  (method POST, optionally)
> * Same characteristics: IP
> * Rate: 30 requests per 1 minute (the free plan allows one rule and a 10 s window; use e.g. 20 per 10 s)
> * Action: Block, duration as long as your plan allows

Many users behind one NAT (a campus network) share one IP and therefore one failure counter.

## Free-plan note

Free Workers plans cap the number of subrequests (KV calls) per request. `create` uses 2 + `count`
KV calls, so on a free plan create at most ~45 keys per click; if a big batch errors, use a smaller count.

## Tests

```
npm test        # node --test tests/*.test.js  (Node 18+, no dependencies)
```

Uses an in-memory fake KV (`tests/fake-kv.js`) and covers key normalizing/hashing/generation, the
activate/check/release state machine, notes, the limiter, the admin endpoint, and the edited
`index.js` / `upload.js`.

`README.md`, `package.json` and `tests/` are not needed on the server. If you upload the whole folder
they are just served as static files; you can leave them out of the upload.
