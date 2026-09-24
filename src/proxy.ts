import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

import { SESSION_COOKIE, readAuthConfig, verifySessionToken } from "./auth/session";
import { DEVICE_COOKIE, DEVICE_COOKIE_OPTIONS, resolveDeviceId } from "./generation/device";

/* Reachable without a session when the studio is closed: the login page and
   the metadata files crawlers and installers ask for. */
const PUBLIC_PATHS = new Set(["/login", "/robots.txt", "/sitemap.xml", "/manifest.webmanifest"]);

export async function proxy(request: NextRequest) {
  const denied = await gate(request);
  if (denied) return denied;

  if (request.nextUrl.pathname.startsWith("/api")) return NextResponse.next();
  const { deviceId, minted } = resolveDeviceId(request.cookies.get(DEVICE_COOKIE)?.value);
  if (!minted) return NextResponse.next();
  const response = NextResponse.next();
  response.cookies.set(DEVICE_COOKIE, deviceId, DEVICE_COOKIE_OPTIONS);
  return response;
}

async function gate(request: NextRequest): Promise<NextResponse | null> {
  const config = readAuthConfig();
  if (config.mode === "open") return null;
  if (config.mode === "misconfigured") {
    console.error("[auth] studio closed:", config.reason);
    return new NextResponse("Login is misconfigured on this server.", { status: 503 });
  }

  const { pathname, search } = request.nextUrl;
  if (PUBLIC_PATHS.has(pathname)) return null;
  const user = await verifySessionToken(config, request.cookies.get(SESSION_COOKIE)?.value);
  if (user) return null;

  // Uploads and server actions are fetches, not navigations: answer, don't redirect.
  if (pathname.startsWith("/api") || request.headers.has("next-action")) {
    return new NextResponse(null, { status: 401 });
  }
  const login = new URL("/login", request.url);
  if (pathname !== "/" || search) login.searchParams.set("next", `${pathname}${search}`);
  return NextResponse.redirect(login);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)"],
};
