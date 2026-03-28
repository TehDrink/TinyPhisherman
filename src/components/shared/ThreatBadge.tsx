import { Badge } from "@/components/ui/badge";
import type { ThreatLevel } from "@/types";

const config: Record<ThreatLevel, { label: string; className: string }> = {
  Low:      { label: "Low",      className: "bg-green-500/20 text-green-400 border-green-500/30" },
  Medium:   { label: "Medium",   className: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" },
  High:     { label: "High",     className: "bg-orange-500/20 text-orange-400 border-orange-500/30" },
  Critical: { label: "Critical", className: "bg-red-500/20 text-red-400 border-red-500/30" },
};

export function ThreatBadge({ level }: { level: ThreatLevel }) {
  const { label, className } = config[level];
  return (
    <Badge variant="outline" className={`font-semibold text-xs px-2 py-0.5 ${className}`}>
      {label}
    </Badge>
  );
}
