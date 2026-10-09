import config from "../config.ts";
import crypto from "node:crypto";
import type { CookieOptions, Request, Response } from "express";

const SESSION_COOKIE = "wp_session";
const TX_COOKIE = "wp_oidc_tx";
const SESSION_MAX_AGE_SECONDS = 30 * 24 * 60 * 60;
const TX_MAX_AGE_SECONDS = 10 * 60;

type Discovery = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
};
type Session = { sub: string; name?: string; exp: number };
type LoginTx = {
  state: string;
  nonce: string;
  verifier: string;
  returnTo: string;
  exp: number;
};

export function isOidcConfigured() {
  return Boolean(
    config.OIDC_ISSUER &&
      config.OIDC_CLIENT_ID &&
      config.OIDC_CLIENT_SECRET &&
      config.OIDC_REDIRECT_URI &&
      config.SESSION_SECRET,
  );
}

let discoveryPromise: Promise<Discovery> | undefined;
function getDiscovery() {
  if (!discoveryPromise) {
    const url =
      config.OIDC_ISSUER.replace(/\/+$/, "") +
      "/.well-known/openid-configuration";
    discoveryPromise = fetch(url).then(async (resp) => {
      if (!resp.ok) {
        throw new Error("OIDC discovery failed: " + resp.status);
      }
      return (await resp.json()) as Discovery;
    });
    // Retry discovery on the next request if it failed
    discoveryPromise.catch(() => {
      discoveryPromise = undefined;
    });
  }
  return discoveryPromise;
}

const nowSeconds = () => Math.floor(Date.now() / 1000);
const randomString = () => crypto.randomBytes(32).toString("base64url");
const hmac = (body: string) =>
  crypto.createHmac("sha256", config.SESSION_SECRET).update(body).digest();

function sign(payload: object) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return body + "." + hmac(body).toString("base64url");
}

function verify<T extends { exp: number }>(value: string | undefined) {
  if (!value || !config.SESSION_SECRET) {
    return undefined;
  }
  const [body, mac] = value.split(".");
  if (!body || !mac) {
    return undefined;
  }
  const expected = hmac(body);
  const actual = Buffer.from(mac, "base64url");
  if (
    actual.length !== expected.length ||
    !crypto.timingSafeEqual(actual, expected)
  ) {
    return undefined;
  }
  try {
    const payload = JSON.parse(
      Buffer.from(body, "base64url").toString(),
    ) as T;
    return payload.exp > nowSeconds() ? payload : undefined;
  } catch {
    return undefined;
  }
}

function getCookie(req: Request, name: string) {
  for (const part of req.headers.cookie?.split(";") ?? []) {
    const index = part.indexOf("=");
    if (index > -1 && part.slice(0, index).trim() === name) {
      return decodeURIComponent(part.slice(index + 1).trim());
    }
  }
  return undefined;
}

function cookieOptions(maxAgeSeconds: number): CookieOptions {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: config.OIDC_REDIRECT_URI.startsWith("https://"),
    path: "/",
    maxAge: maxAgeSeconds * 1000,
  };
}

// Frontend origins allowed to send the session cookie and be redirected back to after login
export function getAllowedOrigins() {
  const origins = new Set<string>();
  if (config.OIDC_REDIRECT_URI) {
    origins.add(new URL(config.OIDC_REDIRECT_URI).origin);
  }
  for (const origin of config.OIDC_ALLOWED_ORIGINS.split(",")) {
    if (origin.trim()) {
      origins.add(origin.trim().replace(/\/+$/, ""));
    }
  }
  return origins;
}

function safeReturnTo(value: unknown) {
  if (typeof value !== "string") {
    return "/";
  }
  // Same-server path, but not protocol-relative (//host or /\host)
  if (/^\/(?![/\\])/.test(value)) {
    return value;
  }
  try {
    const url = new URL(value);
    return getAllowedOrigins().has(url.origin) ? url.toString() : "/";
  } catch {
    return "/";
  }
}

export function getSession(req: Request) {
  if (!isOidcConfigured()) {
    return undefined;
  }
  return verify<Session>(getCookie(req, SESSION_COOKIE));
}

export async function handleLogin(req: Request, res: Response) {
  if (!isOidcConfigured()) {
    res.status(500).type("text/plain").send("OIDC is not configured");
    return;
  }
  const discovery = await getDiscovery();
  const tx: LoginTx = {
    state: randomString(),
    nonce: randomString(),
    verifier: randomString(),
    returnTo: safeReturnTo(req.query.returnTo),
    exp: nowSeconds() + TX_MAX_AGE_SECONDS,
  };
  res.cookie(TX_COOKIE, sign(tx), cookieOptions(TX_MAX_AGE_SECONDS));
  const url = new URL(discovery.authorization_endpoint);
  const params = {
    response_type: "code",
    client_id: config.OIDC_CLIENT_ID,
    redirect_uri: config.OIDC_REDIRECT_URI,
    scope: "openid profile email",
    state: tx.state,
    nonce: tx.nonce,
    code_challenge: crypto
      .createHash("sha256")
      .update(tx.verifier)
      .digest("base64url"),
    code_challenge_method: "S256",
  };
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }
  res.redirect(url.toString());
}

export async function handleCallback(req: Request, res: Response) {
  const tx = verify<LoginTx>(getCookie(req, TX_COOKIE));
  res.clearCookie(TX_COOKIE, { path: "/" });
  if (!tx || req.query.state !== tx.state) {
    res.status(400).type("text/plain").send("Invalid login state, try again");
    return;
  }
  if (req.query.error || typeof req.query.code !== "string") {
    res
      .status(401)
      .type("text/plain")
      .send("Login failed: " + String(req.query.error ?? "missing code"));
    return;
  }
  const discovery = await getDiscovery();
  const tokenResp = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization:
        "Basic " +
        Buffer.from(
          encodeURIComponent(config.OIDC_CLIENT_ID) +
            ":" +
            encodeURIComponent(config.OIDC_CLIENT_SECRET),
        ).toString("base64"),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: req.query.code,
      redirect_uri: config.OIDC_REDIRECT_URI,
      code_verifier: tx.verifier,
    }),
  });
  if (!tokenResp.ok) {
    console.log("OIDC token exchange failed", await tokenResp.text());
    res.status(401).type("text/plain").send("Login failed");
    return;
  }
  const { id_token } = (await tokenResp.json()) as { id_token?: string };
  // The signature isn't checked because the token came directly from the token endpoint
  // over TLS with client authentication (OIDC Core 3.1.3.7), but the claims still are
  const claims = JSON.parse(
    Buffer.from(id_token?.split(".")[1] ?? "", "base64url").toString() || "{}",
  );
  const audience = ([] as string[]).concat(claims.aud ?? []);
  if (
    !claims.sub ||
    claims.iss !== discovery.issuer ||
    !audience.includes(config.OIDC_CLIENT_ID) ||
    (audience.length > 1 && claims.azp !== config.OIDC_CLIENT_ID) ||
    !(claims.exp > nowSeconds()) ||
    claims.nonce !== tx.nonce
  ) {
    console.log("OIDC ID token rejected", claims);
    res.status(401).type("text/plain").send("Login failed");
    return;
  }
  const session: Session = {
    sub: claims.sub,
    name: claims.preferred_username ?? claims.name ?? claims.email,
    exp: nowSeconds() + SESSION_MAX_AGE_SECONDS,
  };
  res.cookie(
    SESSION_COOKIE,
    sign(session),
    cookieOptions(SESSION_MAX_AGE_SECONDS),
  );
  res.redirect(tx.returnTo);
}
