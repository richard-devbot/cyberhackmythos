"use client";

import { Card } from "@/components/ui/card";
import type { Finding } from "@/lib/types";
import { severityCounts } from "@/lib/severity";
import { cn } from "@/lib/utils";

function Kpi({
  label,
  value,
  accent,
  emphasize,
}: {
  label: string;
  value: number;
  accent: string;
  emphasize?: boolean;
}) {
  return (
    <Card
      className={cn(
        "relative gap-0 overflow-hidden p-4",
        emphasize && value > 0 && "ring-1 ring-inset",
      )}
      style={emphasize && value > 0 ? { boxShadow: `inset 0 0 0 1px ${accent}33` } : undefined}
    >
      <span
        className="absolute inset-x-0 top-0 h-0.5"
        style={{ background: accent, opacity: 0.7 }}
      />
      <div className="font-mono text-3xl font-bold tabular-nums" style={{ color: accent }}>
        {value}
      </div>
      <div className="mt-1.5 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
        {label}
      </div>
    </Card>
  );
}

export function KpiStrip({ findings }: { findings: Finding[] }) {
  const c = severityCounts(findings);
  const actNow = findings.filter((f) => f.priority === "act_now").length;
  const kev = findings.filter((f) => f.kev).length;

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      <Kpi label="findings" value={findings.length} accent="var(--foreground)" />
      <Kpi label="act now" value={actNow} accent="#ff4d5e" emphasize />
      <Kpi label="critical" value={c.critical} accent="#ff4d5e" />
      <Kpi label="high" value={c.high} accent="#ff8a3d" />
      <Kpi label="on cisa kev" value={kev} accent="#ff4d5e" emphasize />
    </div>
  );
}
