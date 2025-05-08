import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SQL Injection Scanner Dashboard",
  description: "Frontend for SQL Injection Scanner",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}