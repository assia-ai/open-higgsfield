import { createHmac, randomBytes } from "node:crypto";

/* Uploads to any S3-compatible store (MinIO, R2, AWS S3) instead of Vercel
   Blob. The browser posts the file straight to the bucket with a signed POST
   policy, so the bytes never pass through this server, and the policy pins the
   key, the content type and a size ceiling.

     S3_ENDPOINT=https://minio.example.com     API origin, path-style
     S3_BUCKET=openhiggsfield
     S3_ACCESS_KEY_ID=...
     S3_SECRET_ACCESS_KEY=...
     S3_REGION=us-east-1                       optional
     S3_PUBLIC_URL=https://cdn.example.com/x   optional, defaults to endpoint/bucket
     S3_MAX_UPLOAD_MB=500                      optional

   The public URL must be reachable from the internet: the generation API
   fetches every input from it. */

export type S3Config = {
  endpoint: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  publicUrl: string;
  maxBytes: number;
};

export type PresignedPost = {
  url: string;
  fields: Record<string, string>;
  publicUrl: string;
};

const POLICY_TTL_SECONDS = 10 * 60;

/** Null when S3 is not configured, so uploads keep going to Vercel Blob. */
export function readS3Config(): S3Config | null {
  const endpoint = process.env.S3_ENDPOINT?.trim().replace(/\/+$/, "");
  if (!endpoint) return null;
  const bucket = process.env.S3_BUCKET?.trim();
  const accessKeyId = process.env.S3_ACCESS_KEY_ID?.trim();
  const secretAccessKey = process.env.S3_SECRET_ACCESS_KEY?.trim();
  if (!bucket || !accessKeyId || !secretAccessKey) {
    throw new Error("S3_ENDPOINT needs S3_BUCKET, S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY");
  }
  const maxMb = Number(process.env.S3_MAX_UPLOAD_MB ?? 500);
  return {
    endpoint,
    bucket,
    accessKeyId,
    secretAccessKey,
    region: process.env.S3_REGION?.trim() || "us-east-1",
    publicUrl: (process.env.S3_PUBLIC_URL?.trim() || `${endpoint}/${bucket}`).replace(/\/+$/, ""),
    maxBytes: Math.round((Number.isFinite(maxMb) && maxMb > 0 ? maxMb : 500) * 1024 * 1024),
  };
}

/** A random prefix keeps two uploads of the same file name apart. */
export function uniqueKey(pathname: string): string {
  const slash = pathname.lastIndexOf("/");
  const suffix = randomBytes(6).toString("hex");
  return `${pathname.slice(0, slash + 1)}${suffix}-${pathname.slice(slash + 1)}`;
}

/** Signature V4 POST policy, as in the S3 "browser-based uploads" scheme. */
export function presignPost(
  config: S3Config,
  key: string,
  contentType: string,
  now: Date = new Date(),
): PresignedPost {
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const day = amzDate.slice(0, 8);
  const credential = `${config.accessKeyId}/${day}/${config.region}/s3/aws4_request`;
  const expiration = new Date(now.getTime() + POLICY_TTL_SECONDS * 1000).toISOString();

  const fields: Record<string, string> = {
    key,
    "Content-Type": contentType,
    "x-amz-algorithm": "AWS4-HMAC-SHA256",
    "x-amz-credential": credential,
    "x-amz-date": amzDate,
  };
  const policy = Buffer.from(
    JSON.stringify({
      expiration,
      conditions: [
        { bucket: config.bucket },
        ...Object.entries(fields).map(([name, value]) => ({ [name]: value })),
        ["content-length-range", 1, config.maxBytes],
      ],
    }),
  ).toString("base64");

  return {
    url: `${config.endpoint}/${config.bucket}`,
    fields: { ...fields, policy, "x-amz-signature": signPolicy(config, day, policy) },
    publicUrl: `${config.publicUrl}/${key.split("/").map(encodeURIComponent).join("/")}`,
  };
}

export function signPolicy(config: S3Config, day: string, policy: string): string {
  const signingKey = ["s3", "aws4_request"].reduce<Buffer>(
    (key, part) => hmac(key, part),
    hmac(hmac(`AWS4${config.secretAccessKey}`, day), config.region),
  );
  return createHmac("sha256", signingKey).update(policy).digest("hex");
}

function hmac(key: string | Buffer, data: string): Buffer {
  return createHmac("sha256", key).update(data).digest();
}
