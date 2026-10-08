
const encoder = new TextEncoder();

function hex(buffer) {
  return [...new Uint8Array(buffer)]
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

async function digest(value) {
  return hex(await crypto.subtle.digest(
    "SHA-256", encoder.encode(value)
  ));
}

async function signature(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  return hex(await crypto.subtle.sign(
    "HMAC", key, encoder.encode(value)
  ));
}

function equal(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    diff |= (x[i] || 0) ^ (y[i] || 0);
  }
  return diff === 0;
}

function page(error = "") {
  const html = `<!doctype html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>閲覧認証</title>
<style>
body{font-family:system-ui,sans-serif;background:#f5f6f8;
display:grid;place-items:center;min-height:100vh;margin:0}
main{background:white;padding:36px;border-radius:12px;
box-shadow:0 4px 24px #0001;width:min(340px,80vw)}
h1{font-size:22px}
input,button{box-sizing:border-box;width:100%;padding:13px;
margin-top:12px;border-radius:6px}
input{border:1px solid #ccc}
button{background:#202b40;color:white;border:0;cursor:pointer}
p{color:#b42318}
</style>
</head>
<body><main>
<h1>パスワード認証</h1>
<p>${error ? "パスワードが違います。" : ""}</p>
<form method="POST" action="/__login">
<input type="password" name="password"
placeholder="共通パスワード" required autofocus>
<button type="submit">ログイン</button>
</form>
</main></body></html>`;
  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
    }
  });
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const method = request.method;

  if (!env.SITE_PASSWORD || !env.AUTH_SECRET ||
      env.AUTH_SECRET.length < 32) {
    return new Response("Authentication not configured", {
      status: 503
    });
  }

  const cookie = request.headers.get("Cookie") || "";
  const token = cookie.match(/(?:^|;\s*)site_auth=([^;]+)/)?.[1];

  let authenticated = false;
  if (token) {
    const parts = token.split(".");
    if (parts.length === 2) {
      const [expiry, mac] = parts;
      const expires = Number(expiry);
      if (/^\d+$/.test(expiry) &&
          Number.isSafeInteger(expires) &&
          expires > Date.now() &&
          expires <= Date.now() + 86400000) {
        const expected = await signature(expiry, env.AUTH_SECRET);
        authenticated = equal(mac, expected);
      }
    }
  }

  if (url.pathname === "/__logout") {
    return new Response(null, {
      status: 303,
      headers: {
        Location: "/",
        "Set-Cookie":
          "site_auth=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        "Cache-Control": "no-store"
      }
    });
  }

  if (url.pathname === "/__login" && method === "POST") {
    const type = request.headers.get("Content-Type") || "";
    if (!type.startsWith("application/x-www-form-urlencoded")) {
      return new Response("Invalid request", { status: 400 });
    }

    if (Number(request.headers.get("Content-Length") || 0) > 4096) {
      return new Response("Request too large", { status: 413 });
    }

    const body = await request.text();
    if (body.length > 4096) {
      return new Response("Request too large", { status: 413 });
    }

    const password = new URLSearchParams(body).get("password") || "";
    const correct = equal(
      await digest(password),
      await digest(env.SITE_PASSWORD)
    );

    if (!correct) return page(true);

    const expiry = String(Date.now() + 86400000);
    const mac = await signature(expiry, env.AUTH_SECRET);

    return new Response(null, {
      status: 303,
      headers: {
        Location: "/",
        "Set-Cookie":
          `site_auth=${expiry}.${mac}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
        "Cache-Control": "no-store"
      }
    });
  }

  if (!authenticated) {
    if (method !== "GET" && method !== "HEAD") {
      return new Response("Unauthorized", { status: 401 });
    }
    return page();
  }

  return context.next();
}

