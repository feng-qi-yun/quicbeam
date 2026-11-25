// Minimal Cloudflare Workers + KV signaling relay for QuicBeam.
// Stores ONLY opaque AES-256-GCM ciphertexts (encrypted client-side with PSK).
//
// Setup:
//   1. Create a KV namespace and bind it as `QUICBEAM_KV`.
//   2. (Optional) Set secret `SIGNAL_TOKEN` for Bearer authentication.
//   3. Deploy this script as a Cloudflare Worker.
//
// API:
//   PUT /<room>/<role>  -> stores ciphertext with 24h TTL
//   GET /<room>/<role>  -> returns ciphertext (or 404)

export default {
  async fetch(request, env) {
    if (env.SIGNAL_TOKEN) {
      const auth = request.headers.get("Authorization") || "";
      if (auth !== `Bearer ${env.SIGNAL_TOKEN}`) {
        return new Response("unauthorized", { status: 401 });
      }
    }

    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length !== 2) {
      return new Response("not found", { status: 404 });
    }

    const key = `room:${parts[0]}:${parts[1]}`;
    if (request.method === "PUT") {
      const body = await request.text();
      if (!body || body.length > 8192) {
        return new Response("invalid payload", { status: 400 });
      }
      await env.QUICBEAM_KV.put(key, body, { expirationTtl: 86400 });
      return new Response("ok", { status: 200 });
    }

    if (request.method === "GET") {
      const val = await env.QUICBEAM_KV.get(key);
      if (!val) {
        return new Response("not found", { status: 404 });
      }
      return new Response(val, {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    }

    return new Response("method not allowed", { status: 405 });
  },
};
