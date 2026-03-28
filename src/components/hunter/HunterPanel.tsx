"use client";

import { useState } from "react";
import { Crosshair, Eye, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ThreatBadge } from "@/components/shared/ThreatBadge";
import type { HuntResult, TyposquatVariant, ApiResponse } from "@/types";

export function HunterPanel() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<HuntResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleHunt() {
    if (!domain.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);

    try {
      const res = await fetch("/api/hunt", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domain.trim() }),
      });
      const data: ApiResponse<HuntResult> = await res.json();

      if (!data.ok) {
        setError(data.error);
      } else {
        setResult(data.data);
      }
    } catch {
      setError("Network error — could not reach the hunt API.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Input bar */}
      <Card className="border-zinc-800 bg-zinc-900/50">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <Input
              placeholder="Enter your brand domain… e.g. google.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleHunt()}
              className="bg-zinc-800 border-zinc-700 text-white placeholder:text-zinc-500 flex-1"
            />
            <Button
              onClick={handleHunt}
              disabled={loading || !domain.trim()}
              className="bg-purple-500 hover:bg-purple-400 text-white font-semibold min-w-[110px]"
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <span className="animate-spin h-4 w-4 border-2 border-white/30 border-t-white rounded-full" />
                  Hunting…
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <Crosshair className="h-4 w-4" />
                  Hunt
                </span>
              )}
            </Button>
          </div>
          {loading && (
            <p className="text-xs text-zinc-400 mt-2 animate-pulse">
              Generating typosquat variants → deploying agents → comparing visuals…
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
          {/* Summary */}
          <div className="flex items-center gap-4">
            <p className="text-sm text-zinc-400">
              Found{" "}
              <span className="text-white font-semibold">
                {result.variants.filter((v) => v.liveStatus === "live").length}
              </span>{" "}
              live variants for{" "}
              <span className="text-purple-400 font-mono">{result.originalDomain}</span>
            </p>
            {result.variants.some((v) => v.threatLevel === "Critical") && (
              <Alert className="border-red-800 bg-red-950/30 py-1 px-3 flex-1">
                <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
                <AlertDescription className="text-red-300 text-xs">
                  Critical threat detected — at least one domain is a near-identical clone
                </AlertDescription>
              </Alert>
            )}
          </div>

          {/* Side-by-side original screenshot */}
          {result.originalScreenshot && (
            <Card className="border-zinc-800 bg-zinc-900/50">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium text-zinc-400">
                  Original — {result.originalDomain}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={`data:image/png;base64,${result.originalScreenshot}`}
                  alt={`Screenshot of ${result.originalDomain}`}
                  className="rounded-lg border border-zinc-700 w-full object-cover max-h-48"
                />
              </CardContent>
            </Card>
          )}

          {/* Variant cards */}
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {result.variants.map((variant) => (
              <VariantCard key={variant.domain} variant={variant} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function VariantCard({ variant }: { variant: TyposquatVariant }) {
  const isUnreachable = variant.liveStatus === "unreachable";

  return (
    <Card
      className={`border-zinc-800 bg-zinc-900/50 ${
        variant.threatLevel === "Critical" ? "ring-1 ring-red-500/50" : ""
      }`}
    >
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <p className="text-sm font-mono text-zinc-200 break-all">{variant.domain}</p>
          <ThreatBadge level={variant.threatLevel} />
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {isUnreachable ? (
          <p className="text-xs text-zinc-500 italic">Domain unreachable</p>
        ) : (
          <>
            {/* Visual similarity bar */}
            <div>
              <div className="flex justify-between text-xs text-zinc-500 mb-1">
                <span className="flex items-center gap-1">
                  <Eye className="h-3 w-3" />
                  Visual Similarity
                </span>
                <span
                  className={
                    variant.visualSimilarity > 80
                      ? "text-red-400 font-semibold"
                      : variant.visualSimilarity > 60
                      ? "text-orange-400"
                      : "text-zinc-400"
                  }
                >
                  {variant.visualSimilarity}%
                </span>
              </div>
              <Progress value={variant.visualSimilarity} className="h-1.5 bg-zinc-800" />
            </div>

            {/* Manipulation score */}
            <div>
              <div className="flex justify-between text-xs text-zinc-500 mb-1">
                <span>Manipulation Score</span>
                <span>{variant.manipulationScore}/100</span>
              </div>
              <Progress value={variant.manipulationScore} className="h-1.5 bg-zinc-800" />
            </div>

            <p className="text-xs text-zinc-500">
              Category:{" "}
              <span
                className={
                  variant.squatterCategory === "Credential Harvester" ||
                  variant.squatterCategory === "Malware Drop"
                    ? "text-red-400 font-medium"
                    : "text-zinc-300"
                }
              >
                {variant.squatterCategory}
              </span>
            </p>

            {/* Screenshot thumbnail */}
            {variant.screenshot && (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={`data:image/png;base64,${variant.screenshot}`}
                alt={`Screenshot of ${variant.domain}`}
                className="rounded border border-zinc-700 w-full object-cover max-h-28"
              />
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
