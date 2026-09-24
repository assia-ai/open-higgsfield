"use server";

import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";

import {
  SESSION_COOKIE,
  SESSION_COOKIE_OPTIONS,
  checkPassword,
  createSessionToken,
  readAuthConfig,
  safeNextPath,
  verifySessionToken,
} from "./session";

/** `user` refills the field: React resets an action form after every submit. */
export type LoginState = { error: string | null; user: string };

/* Failed attempts per client address, in this process's memory. Enough to slow
   a password guesser on a single-instance self-host; it resets on restart. */
const FAILURE_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES = 10;
const failures = new Map<string, { count: number; since: number }>();

export async function login(_previous: LoginState, form: FormData): Promise<LoginState> {
  const config = readAuthConfig();
  if (config.mode === "open") redirect("/");
  const user = String(form.get("user") ?? "").trim();
  if (config.mode === "misconfigured") {
    return { error: `Login misconfigured: ${config.reason}`, user };
  }

  const client = await clientAddress();
  const record = failures.get(client);
  if (record && Date.now() - record.since > FAILURE_WINDOW_MS) failures.delete(client);
  if ((failures.get(client)?.count ?? 0) >= MAX_FAILURES) {
    return { error: "Too many attempts. Try again in a few minutes.", user };
  }

  const password = String(form.get("password") ?? "");
  if (!(await checkPassword(config, user, password))) {
    const current = failures.get(client);
    failures.set(client, { count: (current?.count ?? 0) + 1, since: current?.since ?? Date.now() });
    await new Promise((resolve) => setTimeout(resolve, 400));
    return { error: "Wrong username or password", user };
  }

  failures.delete(client);
  const jar = await cookies();
  jar.set(SESSION_COOKIE, await createSessionToken(config.secret, user), SESSION_COOKIE_OPTIONS);
  redirect(safeNextPath(form.get("next")));
}

export async function logout() {
  const jar = await cookies();
  jar.set(SESSION_COOKIE, "", { ...SESSION_COOKIE_OPTIONS, maxAge: 0 });
  redirect("/login");
}

/** The signed-in user, or null when the studio is open. */
export async function getSessionUser(): Promise<string | null> {
  const config = readAuthConfig();
  if (config.mode !== "closed") return null;
  const jar = await cookies();
  return verifySessionToken(config, jar.get(SESSION_COOKIE)?.value);
}

/* The last X-Forwarded-For hop is the one the reverse proxy (Traefik on
   Coolify) appended; earlier hops are whatever the client chose to send. */
async function clientAddress(): Promise<string> {
  const list = await headers();
  return list.get("x-forwarded-for")?.split(",").pop()?.trim() || list.get("x-real-ip") || "unknown";
}
