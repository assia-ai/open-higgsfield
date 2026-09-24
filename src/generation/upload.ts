import { put } from "@vercel/blob/client";

export async function uploadMedia(file: File): Promise<{ url: string }> {
  const res = await fetch("/api/upload", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ filename: file.name, contentType: file.type }),
  });
  const target = (await res.json().catch(() => null)) as {
    provider?: unknown;
    url?: unknown;
    fields?: unknown;
    publicUrl?: unknown;
    error?: unknown;
  } | null;
  if (!res.ok || !target) {
    throw new Error(typeof target?.error === "string" ? target.error : "Upload failed");
  }
  if (target.provider === "s3") return uploadToS3(file, target);
  return uploadToVercelBlob(file);
}

async function uploadToS3(
  file: File,
  target: { url?: unknown; fields?: unknown; publicUrl?: unknown },
): Promise<{ url: string }> {
  if (typeof target.url !== "string" || typeof target.publicUrl !== "string") {
    throw new Error("Upload failed");
  }
  const form = new FormData();
  for (const [name, value] of Object.entries(target.fields as Record<string, string>)) {
    form.append(name, value);
  }
  // S3 ignores every field after the file, so it goes last.
  form.append("file", file);
  const res = await fetch(target.url, { method: "POST", body: form });
  if (!res.ok) throw new Error(`Storage refused the upload (${res.status})`);
  return { url: target.publicUrl };
}

async function uploadToVercelBlob(file: File): Promise<{ url: string }> {
  const res = await fetch("/api/blob", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      type: "blob.generate-client-token",
      payload: { pathname: file.name, clientPayload: null, multipart: false },
    }),
  });
  if (!res.ok) throw new Error("Failed to retrieve the client token");
  const { clientToken, pathname } = (await res.json()) as {
    clientToken?: unknown;
    pathname?: unknown;
  };
  if (typeof clientToken !== "string" || typeof pathname !== "string") {
    throw new Error("Failed to retrieve the client token");
  }
  const blob = await put(pathname, file, { access: "public", token: clientToken });
  return { url: blob.url };
}
