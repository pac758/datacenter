# LINE Webhook Proxy for Google Apps Script

Use this Cloudflare Worker URL as the LINE Developers webhook URL.

Apps Script `doPost(e)` cannot read request headers, so it cannot verify
`x-line-signature` itself. This Worker verifies the signature with the
Channel Secret and only forwards genuine LINE requests.

## Worker settings (Settings → Variables and Secrets)

| Name                  | Type   | Value                                                     |
| --------------------- | ------ | --------------------------------------------------------- |
| `GAS_WEBHOOK_URL`     | Secret | `https://script.google.com/macros/s/<DEPLOYMENT_ID>/exec` |
| `LINE_CHANNEL_SECRET` | Secret | Channel secret from LINE Developers → Basic settings      |

## Worker code

```js
async function verifyLineSignature(body, signature, channelSecret) {
  if (!signature || !channelSecret) return false;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(channelSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
  const expected = btoa(String.fromCharCode(...new Uint8Array(mac)));

  // Constant-time compare
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  return diff === 0;
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "GET") {
      return new Response("LINE webhook proxy is running", { status: 200 });
    }

    if (request.method !== "POST") {
      return new Response("Method not allowed", {
        status: 405,
        headers: { Allow: "GET, POST" },
      });
    }

    const body = await request.text();
    const signature = request.headers.get("x-line-signature");

    const valid = await verifyLineSignature(body, signature, env.LINE_CHANNEL_SECRET);
    if (!valid) {
      return new Response("Invalid signature", { status: 401 });
    }

    // Do not wait for Apps Script. LINE only needs an immediate HTTP 200.
    // Cloudflare follows the Apps Script 302 redirect while forwarding.
    ctx.waitUntil(
      fetch(env.GAS_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body,
        redirect: "follow",
      }).catch(() => {})
    );

    return new Response("OK", { status: 200 });
  },
};
```
