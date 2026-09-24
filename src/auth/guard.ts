import { cookies } from "next/headers";

import { SESSION_COOKIE, readAuthConfig, verifySessionToken } from "./session";

export class NotSignedInError extends Error {
  constructor() {
    super("Sign in to use the studio");
    this.name = "NotSignedInError";
  }
}

/** The proxy already turns anonymous requests away; server actions and route
    handlers check again so none of them relies on the matcher alone. Resolves
    to the user, or null when the studio is open. */
export async function requireSession(): Promise<string | null> {
  const config = readAuthConfig();
  if (config.mode === "open") return null;
  if (config.mode === "misconfigured") throw new Error(`Login misconfigured: ${config.reason}`);
  const jar = await cookies();
  const user = await verifySessionToken(config, jar.get(SESSION_COOKIE)?.value);
  if (!user) throw new NotSignedInError();
  return user;
}
