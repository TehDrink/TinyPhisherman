import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScannerPanel } from "@/components/scanner/ScannerPanel";
import { HunterPanel } from "@/components/hunter/HunterPanel";
import { Fish, Shield, Crosshair } from "lucide-react";

export default function Home() {
  return (
    <main className="min-h-screen bg-zinc-950 text-white">
      {/* Header */}
      <header className="border-b border-zinc-800 bg-zinc-900/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Fish className="h-6 w-6 text-cyan-400" />
            <span className="text-lg font-bold tracking-tight">
              tiny<span className="text-cyan-400">Phisherman</span>
            </span>
          </div>
          <span className="text-xs text-zinc-500 border border-zinc-700 rounded px-1.5 py-0.5">
            AI-Powered Phishing Detection
          </span>
        </div>
      </header>

      {/* Body */}
      <div className="max-w-5xl mx-auto px-4 py-8">
        {/* Hero */}
        <div className="mb-8 text-center">
          <h1 className="text-3xl font-bold mb-2">
            Proactive{" "}
            <span className="text-cyan-400">Phishing Detection</span>
          </h1>
          <p className="text-zinc-400 max-w-xl mx-auto text-sm">
            Deploys an autonomous AI agent to interact with suspicious sites — bypassing
            anti-bot measures to surface real threats before they reach your users.
          </p>
        </div>

        {/* Feature tabs */}
        <Tabs defaultValue="scanner" className="space-y-6">
          <TabsList className="bg-zinc-900 border border-zinc-800 p-1 w-full sm:w-auto">
            <TabsTrigger
              value="scanner"
              className="flex items-center gap-2 data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400"
            >
              <Shield className="h-4 w-4" />
              Active Scanner
            </TabsTrigger>
            <TabsTrigger
              value="hunter"
              className="flex items-center gap-2 data-[state=active]:bg-purple-500/20 data-[state=active]:text-purple-400"
            >
              <Crosshair className="h-4 w-4" />
              Brand Protection
            </TabsTrigger>
          </TabsList>

          <TabsContent value="scanner" className="mt-0">
            <ScannerPanel />
          </TabsContent>

          <TabsContent value="hunter" className="mt-0">
            <HunterPanel />
          </TabsContent>
        </Tabs>
      </div>
    </main>
  );
}
