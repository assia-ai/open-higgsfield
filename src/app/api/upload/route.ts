import { cookies } from "next/headers";
import { NextResponse } from "next/server";

import { NotSignedInError, requireSession } from "@/auth/guard";
import {
  DEVICE_COOKIE,
  DEVICE_COOKIE_OPTIONS,
  blobPathname,
  resolveDeviceId,
} from "@/generation/device";
import { presignPost, readS3Config, uniqueKey } from "@/generation/s3";
import { UPLOAD_CONTENT_TYPES } from "@/generation/upload-policy";

/* Picks the store for an upload. With S3 configured it answers with a signed
   POST the browser sends straight to the bucket; otherwise it tells the client
   to go through /api/blob as before. */

export async function POST(request: Request): Promise<NextResponse> {
  try {
    await requireSession();
  } catch (error) {
    if (error instanceof NotSignedInError) return new NextResponse(null, { status: 401 });
    throw error;
  }

  const config = readS3Config();
  if (!config) return NextResponse.json({ provider: "vercel-blob" });

  const { filename, contentType } = (await request.json()) as {
    filename?: unknown;
    contentType?: unknown;
  };
  if (typeof filename !== "string" || !filename) {
    return NextResponse.json({ error: "Missing file name" }, { status: 400 });
  }
  if (typeof contentType !== "string" || !UPLOAD_CONTENT_TYPES.includes(contentType)) {
    return NextResponse.json({ error: "This file type cannot be uploaded" }, { status: 400 });
  }

  const jar = await cookies();
  const device = resolveDeviceId(jar.get(DEVICE_COOKIE)?.value);
  const key = uniqueKey(blobPathname(device.deviceId, filename));
  console.info("[upload] s3", { key });

  const response = NextResponse.json({ provider: "s3", ...presignPost(config, key, contentType) });
  if (device.minted) response.cookies.set(DEVICE_COOKIE, device.deviceId, DEVICE_COOKIE_OPTIONS);
  return response;
}
