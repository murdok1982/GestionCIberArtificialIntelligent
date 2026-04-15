import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { headers } from "next/headers";
import "./globals.css";
import { Providers } from "./providers";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "CyberGuard — Security Operations Platform",
  description: "AI-powered cybersecurity monitoring, threat intelligence, and digital forensics",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const headersList = await headers();
  const nonce = headersList.get("x-nonce") ?? "";

  return (
    <html lang="en" className="dark">
      <body
        className={`${inter.className} bg-[#0A0E1A] text-slate-100 antialiased`}
        // Forward nonce so Next.js internal hydration scripts receive it
        {...(nonce ? { "data-nonce": nonce } : {})}
      >
        <Providers nonce={nonce}>{children}</Providers>
      </body>
    </html>
  );
}
