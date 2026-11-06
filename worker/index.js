
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Admin-Key",
  "Content-Type": "application/json; charset=utf-8"
};

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: corsHeaders
  });
}

async function hmac(keyBytes, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
}

function toHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function verifyTelegram(initData, botToken) {
  if (!initData || !botToken) return null;

  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return null;

  params.delete("hash");

  const entries = Array.from(params.entries()).sort((a, b) => a[0].localeCompare(b[0]));
  const checkString = entries.map(([k, v]) => `${k}=${v}`).join("\n");

  const secretKey = await hmac(
    new TextEncoder().encode("WebAppData"),
    new TextEncoder().encode(botToken)
  );

  const signature = await hmac(secretKey, new TextEncoder().encode(checkString));
  if (toHex(signature) !== hash.toLowerCase()) return null;

  const authDate = Number(params.get("auth_date"));
  if (!authDate || Date.now() / 1000 - authDate > 86400 || authDate > Date.now() / 1000 + 60) return null;

  try {
    const user = JSON.parse(params.get("user") || "{}");
    return user.id ? String(user.id) : null;
  } catch {
    return null;
  }
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method !== "POST") {
      return response({ error: "Method not allowed" }, 405);
    }

    const url = new URL(request.url);
    let body;

    try {
      body = await request.json();
    } catch {
      return response({ error: "Invalid JSON" }, 400);
    }

    if (url.pathname === "/check" || url.pathname === "/complete") {
      const telegramId = await verifyTelegram(body.initData, env.BOT_TOKEN);
      if (!telegramId) return response({ error: "Telegram verification failed" }, 401);

      const result = await env.DB.prepare(
        "SELECT paid, completed FROM participants WHERE telegram_id = ?"
      ).bind(telegramId).first();

      const paid = Number(result?.paid || 0) === 1;
      const completed = Number(result?.completed || 0) === 1;

      if (url.pathname === "/check") {
        return response({ ok: true, paid, completed, access: paid && !completed });
      }

      if (!paid) return response({ error: "Payment required" }, 403);
      if (completed) return response({ error: "Story already completed" }, 403);

      await env.DB.prepare(
        "UPDATE participants SET completed = 1 WHERE telegram_id = ? AND paid = 1 AND completed = 0"
      ).bind(telegramId).run();

      return response({ ok: true, completed: true });
    }

    if (url.pathname === "/grant") {
      if (!env.ADMIN_KEY || request.headers.get("X-Admin-Key") !== env.ADMIN_KEY) {
        return response({ error: "Unauthorized" }, 401);
      }

      const telegramId = String(body.telegram_id || "").trim();
      if (!/^\d+$/.test(telegramId)) return response({ error: "Invalid Telegram ID" }, 400);

      await env.DB.prepare(
        `INSERT INTO participants (telegram_id, paid, completed)
         VALUES (?, 1, 0)
         ON CONFLICT(telegram_id) DO UPDATE SET paid = 1`
      ).bind(telegramId).run();

      return response({ ok: true, paid: true });
    }

    return response({ error: "Not found" }, 404);
  }
};

