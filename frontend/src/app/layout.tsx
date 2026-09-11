import type { Metadata } from "next";
import "./globals.css";
import { AppProvider } from "@/context/AppContext";
import { AppShell } from "@/components/layout/AppShell";

export const metadata: Metadata = {
  title: "API Guardian — Apple-Inspired API Security Simulator",
  description:
    "AI-Powered API Security Attack Simulation, Bruno Automated Execution, Fix Verification & Continuous Governance Platform.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="bg-[#FBFBFD] text-[#1D1D1F]">
        <AppProvider>
          <AppShell>{children}</AppShell>
        </AppProvider>
      </body>
    </html>
  );
}
