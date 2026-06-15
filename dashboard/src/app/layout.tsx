import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import Link from "next/link";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "PhoenixSec — Autonomous DevSecOps Security Pipeline",
  description: "Autonomous security scanning, AST analysis, and AI patching dashboard.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}>
      <body className="h-full bg-zinc-950 text-zinc-100 flex overflow-hidden">
        {/* Sidebar Nav */}
        <aside className="w-64 border-r border-zinc-800 bg-zinc-900/50 backdrop-blur-md flex flex-col justify-between shrink-0">
          <div>
            {/* Header / Brand */}
            <div className="p-6 border-b border-zinc-800 flex items-center space-x-3">
              <span className="text-2xl">🔥</span>
              <div>
                <h1 className="text-lg font-bold bg-gradient-to-r from-purple-400 to-pink-500 bg-clip-text text-transparent">
                  PhoenixSec
                </h1>
                <p className="text-xs text-zinc-500 font-mono">v0.2.0 Pipeline</p>
              </div>
            </div>

            {/* Nav Menu */}
            <nav className="p-4 space-y-1">
              <Link
                href="/"
                className="flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/50 transition-all duration-200"
              >
                <span>📊</span>
                <span>Overview</span>
              </Link>
              <Link
                href="/scan"
                className="flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/50 transition-all duration-200"
              >
                <span>🔍</span>
                <span>Security Scan</span>
              </Link>
              <Link
                href="/reports"
                className="flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800/50 transition-all duration-200"
              >
                <span>📁</span>
                <span>Scan Reports</span>
              </Link>
            </nav>
          </div>

          {/* Sidebar Footer */}
          <div className="p-4 border-t border-zinc-800">
            <div className="flex items-center justify-between text-xs text-zinc-500 font-mono">
              <span>Status: Online</span>
              <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
            </div>
          </div>
        </aside>

        {/* Main Dashboard Panel */}
        <main className="flex-1 flex flex-col overflow-hidden bg-zinc-950 glow-bg">
          <header className="h-16 border-b border-zinc-800 bg-zinc-900/20 backdrop-blur-md flex items-center justify-between px-8">
            <h2 className="text-lg font-semibold text-zinc-200">Autonomous Security Control</h2>
            <div className="flex items-center space-x-4">
              <span className="text-xs font-mono bg-zinc-800/50 border border-zinc-700/50 text-zinc-400 px-3 py-1.5 rounded-full">
                API: http://127.0.0.1:8080
              </span>
            </div>
          </header>

          {/* Sub-page viewport */}
          <div className="flex-1 overflow-y-auto p-8">
            {children}
          </div>
        </main>
      </body>
    </html>
  );
}
