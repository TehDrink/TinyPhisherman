import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "tinyPhisherman — AI Phishing Detection",
  description: "Proactive phishing detection powered by TinyFish and OpenAI",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
