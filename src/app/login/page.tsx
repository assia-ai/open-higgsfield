import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { redirect } from "next/navigation";

import { getSessionUser } from "@/auth/actions";
import { readAuthConfig, safeNextPath } from "@/auth/session";
import { LoginForm } from "@/openhiggsfield/login-form";

import "@/openhiggsfield/openhiggsfield.css";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-ohf-inter",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Sign in",
  robots: { index: false, follow: false },
};

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string | string[] }>;
}) {
  const next = safeNextPath((await searchParams).next);
  if (readAuthConfig().mode === "open" || (await getSessionUser())) redirect(next);
  return (
    <div className={`ohf ${inter.variable}`}>
      <LoginForm next={next} />
    </div>
  );
}
