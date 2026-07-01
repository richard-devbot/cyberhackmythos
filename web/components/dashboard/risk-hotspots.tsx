"use client";

import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import type { Finding } from "@/lib/types";
import { SEV_META } from "@/lib/severity";

export function RiskHotspots({ findings }: { findings: Finding[] }) {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = f.package ?? f.file ?? "(unknown)";
    groups.set(key, [...(groups.get(key) ?? []), f]);
  }
  const worstRank = (items: Finding[]) => Math.max(...items.map((x) => SEV_META[x.severity].rank));
  const top = [...groups.entries()].sort((a, b) => worstRank(b[1]) - worstRank(a[1])).slice(0, 7);

  return (
    <Card className="gap-4">
      <CardHeader>
        <CardTitle className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          Risk hotspots
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1">
        {top.map(([name, items]) => {
          const worst = items.reduce((a, b) => (SEV_META[b.severity].rank > SEV_META[a.severity].rank ? b : a));
          return (
            <div key={name} className="flex items-center gap-3 py-1.5 font-mono text-xs">
              <span
                className="h-5 w-[3px] shrink-0 rounded-full"
                style={{ background: SEV_META[worst.severity].color }}
              />
              <span className="flex-1 truncate text-foreground/85" title={name}>
                {name}
              </span>
              <span className="tabular-nums text-muted-foreground">{items.length}</span>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
