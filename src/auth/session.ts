/* Studio login. Accounts come from the environment, so a self-hosted studio can
   be closed without a database:

     STUDIO_USERS="alice:correct-horse,bob:battery-staple"
     STUDIO_AUTH_SECRET=<32+ random characters>

   With STUDIO_USERS unset the studio stays open, as before. With it set but no
   usable secret, every request is refused rather than silently left open.

   Web Crypto only, so this runs unchanged in the proxy, server actions and
   route handlers. */

export const SESSION_COOKIE = "ohf_session";

const SESSION_MAX_AGE = 60 * 60 * 24 * 14;

export const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  path: "/",
  maxAge: SESSION_MAX_AGE,
};

const MIN_SECRET_LENGTH = 32;

export type AuthConfig =
  | { mode: "open" }
  | { mode: "misconfigured"; reason: string }
  | { mode: "closed"; users: Map<string, string>; secret: string };

export function readAuthConfig(): AuthConfig {
  const rawUsers = process.env.STUDIO_USERS?.trim();
  if (!rawUsers) return { mode: "open" };

  const users = new Map<string, string>();
  for (const entry of rawUsers.split(",")) {
    const colon = entry.indexOf(":");
    const user = entry.slice(0, colon).trim();
    const password = entry.slice(colon + 1);
    if (colon <= 0 || !password) {
      return { mode: "misconfigured", reason: "STUDIO_USERS must be user:password pairs" };
    }
    users.set(user, password);
  }

  const secret = process.env.STUDIO_AUTH_SECRET ?? "";
  if (secret.length < MIN_SECRET_LENGTH) {
    return {
      mode: "misconfigured",
      reason: `STUDIO_AUTH_SECRET must be at least ${MIN_SECRET_LENGTH} characters`,
    };
  }
  return { mode: "closed", users, secret };
}

export async function checkPassword(
  config: Extract<AuthConfig, { mode: "closed" }>,
  user: string,
  password: string,
): Promise<boolean> {
  // Compared as MACs so neither the length nor the prefix of a stored password
  // leaks through timing, and an unknown user costs the same as a wrong password.
  const expected = config.users.get(user) ?? "";
  const [a, b] = await Promise.all([
    mac(config.secret, `password:${expected}`),
    mac(config.secret, `password:${password}`),
  ]);
  return config.users.has(user) && equalBytes(a, b);
}

export async function createSessionToken(secret: string, user: string): Promise<string> {
  const expires = Math.floor(Date.now() / 1000) + SESSION_MAX_AGE;
  const payload = `${toBase64Url(new TextEncoder().encode(user))}.${expires}`;
  return `${payload}.${toBase64Url(await mac(secret, `session:${payload}`))}`;
}

/** The signed-in user, or null. A user removed from STUDIO_USERS is signed out. */
export async function verifySessionToken(
  config: Extract<AuthConfig, { mode: "closed" }>,
  token: string | undefined,
): Promise<string | null> {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [userPart, expiresPart, signature] = parts as [string, string, string];

  const expected = await mac(config.secret, `session:${userPart}.${expiresPart}`);
  const given = fromBase64Url(signature);
  if (!given || !equalBytes(expected, given)) return null;

  const expires = Number(expiresPart);
  if (!Number.isInteger(expires) || expires * 1000 < Date.now()) return null;

  const userBytes = fromBase64Url(userPart);
  if (!userBytes) return null;
  const user = new TextDecoder().decode(userBytes);
  return config.users.has(user) ? user : null;
}

/** Only same-origin paths survive the round trip through the login page. */
export function safeNextPath(raw: unknown): string {
  if (typeof raw !== "string" || !raw.startsWith("/") || raw.startsWith("//")) return "/";
  if (raw.startsWith("/login")) return "/";
  return raw;
}

async function mac(secret: string, message: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}

function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64Url(text: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  try {
    const binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}
