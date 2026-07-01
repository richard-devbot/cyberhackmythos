"use client";

import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import type { Finding, Severity } from "@/lib/types";
import { SEV_META, severityCounts } from "@/lib/severity";
import { Cell, Pie, PieChart } from "recharts";

const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function SeverityRing({ findings }: { findings: Finding[] }) {
  const counts = severityCounts(findings);
  const data = ORDER.filter((s) => counts[s] > 0).map((s) => ({
    name: SEV_META[s].label,
    value: counts[s],
    color: SEV_META[s].color,
  }));

  return (
    <Card className="gap-4">
      <CardHeader>
        <CardTitle className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          Severity distribution
        </CardTitle>
      </CardHeader>
      <CardContent className="flex items-center gap-5">
        <div className="relative size-[132px] shrink-0">
          <PieChart width={132} height={132}>
            <Pie
              data={data.length ? data : [{ name: "none", value: 1, color: "#1e2a41" }]}
              dataKey="value"
              cx="50%"
              cy="50%"
              innerRadius={44}
              outerRadius={64}
              startAngle={90}
              endAngle={-270}
              stroke="none"
              paddingAngle={data.length > 1 ? 2 : 0}
              isAnimationActive={false}
            >
              {(data.length ? data : [{ color: "#1e2a41" }]).map((d, i) => (
                <Cell key={i} fill={d.color} />
              ))}
            </Pie>
          </PieChart>
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span className="font-mono text-2xl font-bold tabular-nums">{findings.length}</span>
            <span className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">
              total
            </span>
          </div>
        </div>

        <ul className="flex-1 space-y-1.5 font-mono text-xs">
          {ORDER.map((s) => (
            <li key={s} className="flex items-center gap-2.5">
              <span aria-hidden className="w-3 text-center" style={{ color: SEV_META[s].color }}>
                {SEV_META[s].shape}
              </span>
              <span className="flex-1 capitalize text-muted-foreground">{s}</span>
              <span className="tabular-nums text-foreground">{counts[s]}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
