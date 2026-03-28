"use client";

import { useState } from "react";
import { Search, Shield, AlertTriangle, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ThreatBadge } from "@/components/shared/ThreatBadge";
import type { ScanResult, ApiResponse } from "@/types";

export function ScannerPanel() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleScan() {
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() }),
      });
      const data: ApiResponse<ScanResult> = await res.json();

      if (!data.ok) {
        setError(data.error);
      } else {
        setResult(data.data);
      }
    } catch {
      setError("Network error — could not reach the scan API.");
    } finally {
      setLoading(false);
    }
  }

  const threatColor: Record<string, string> = {
    Low:      "text-green-400",
    Medium:   "text-yellow-400",
    High:     "text-orange-400",
    Critical: "text-red-400",
  };

  return (
    <div className="space-y-6">
      {/* Input bar */}
      <Card className="border-zinc-800 bg-zinc-900/50">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <Input
              placeholder="Enter suspicious URL… e.g. paypa1-secure.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 flex-1"
            />
            <Button
              onClick={handleScan}
              disabled={loading || !url.trim()}
              className="bg-cyan-500 hover:bg-cyan-400 text-black font-semibold min-w-[110px]"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <span className="animate-spin h-4 w-4 border-2 border-black/30 border-t-black rounded-full" />
                  Scanning…
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Search className="h-4 w-4" />
                  Scan
                </span>
              )}
            </Button>
          </div>
          {loading && (
            <p className="text-xs text-zinc-400 mt-2 animate-pulse">
              Deploying AI agent → navigating target → analysing content…
            </p>
          )}
        </CardContent>
      </Card>

      {/* Error */}
      {error && (
        <Alert className="border-red-800 bg-red-950/30">
          <AlertTriangle className="h-4 w-4 text-red-400" />
          <AlertDescription className="text-red-300">{error}</AlertDescription>
        </Alert>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-4">
          {/* Threat level hero */}
          <Card className="border-zinc-800 bg-zinc-900/50">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium text-zinc-400 flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Threat Assessment
                </CardTitle>
                <ThreatBadge level={result.threatLevel} />
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-3">
                <span className={`text-5xl font-bold tabular-nums ${threatColor[result.threatLevel]}`}>
                  {result.manipulationScore}
                </span>
                <div>
                  <p className="text-xs text-zinc-500 uppercase tracking-wide">Manipulation Score</p>
                  <p className="text-sm text-zinc-300">{result.squatterCategory}</p>
                </div>
              </div>

              <Progress
                value={result.manipulationScore}
                className="h-2 bg-zinc-800"
              />

              <p className="text-sm text-zinc-300 leading-relaxed">{result.reasoning}</p>

              {result.redFlags.length > 0 && (
                <div className="space-y-1">
                  <p className="text-xs font-semibold text-zinc-500 uppercase tracking-wide">Red Flags</p>
                  <ul className="space-y-1">
                    {result.redFlags.map((flag, i) => (
                      <li key={i} className="flex items-start gap-2 text-sm text-red-300">
                        <span className="mt-1 h-1.5 w-1.5 rounded-full bg-red-400 shrink-0" />
                        {flag}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Passive checks */}
          <Card className="border-zinc-800 bg-zinc-900/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-zinc-400">Passive Signals</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Metric
                  label="Domain Age"
                  value={
                    result.passiveChecks.domainAgeDays !== null
                      ? `${result.passiveChecks.domainAgeDays}d`
                      : "Unknown"
                  }
                  warn={(result.passiveChecks.domainAgeDays ?? 999) < 30}
                />
                <Metric
                  label="SSL"
                  value={result.passiveChecks.hasSSL ? "Valid" : "None"}
                  warn={!result.passiveChecks.hasSSL}
                />
                <Metric
                  label="Redirects"
                  value={String(result.passiveChecks.redirectCount)}
                  warn={result.passiveChecks.redirectCount > 2}
                />
                <Metric
                  label="Registrar"
                  value={result.passiveChecks.registrar ?? "—"}
                />
              </div>
            </CardContent>
          </Card>

          {/* Screenshot */}
          {result.screenshot && (
            <Card className="border-zinc-800 bg-zinc-900/50">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400 flex items-center gap-2">
                  <ExternalLink className="h-4 w-4" />
                  Live Screenshot
                </CardTitle>
              </CardHeader>
              <CardContent>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={`data:image/png;base64,${result.screenshot}`}
                  alt="Screenshot of scanned site"
                  className="rounded-lg border border-zinc-700 w-full object-cover max-h-72"
                />
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function Metric({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="rounded-lg bg-zinc-800/60 px-3 py-2">
      <p className="text-xs text-zinc-500 mb-0.5">{label}</p>
      <p className={`text-sm font-medium ${warn ? "text-orange-400" : "text-zinc-200"}`}>{value}</p>
    </div>
  );
}
