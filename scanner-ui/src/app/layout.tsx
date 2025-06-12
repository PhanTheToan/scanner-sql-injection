import type { Metadata } from "next";
import { Outfit } from "next/font/google";
import "./globals.css";

// Import font
const outfit = Outfit({ 
  subsets: ["latin"],
  display: "swap",
  variable: "--font-outfit"
});

export const metadata: Metadata = {
  title: "SQL Injection Scanner Dashboard",
  description: "Frontend for SQL Injection Scanner with modern UI",
  keywords: "SQL injection, security scanning, web security",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${outfit.variable}`}>
      <head>
        <link rel="icon" href="/favicon.ico" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="theme-color" content="#0f172a" />
      </head>
      <body className="bg-gray-950 font-sans">
        {/* Add a subtle background pattern */}
        <div className="fixed inset-0 z-[-1] bg-[radial-gradient(#1a2033_1px,transparent_1px)] opacity-50 [background-size:16px_16px]"></div>
        
        {/* Main content */}
        <div className="mx-auto max-w-7xl">
          {children}
        </div>
      </body>
    </html>
  );
}