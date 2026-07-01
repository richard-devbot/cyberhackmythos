"use client";

import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import type { Finding } from "@/lib/types";
import { STRIDE_ORDER, strideOf } from "@/lib/severity";

export function StridePanel({ findings }: { findings: Finding[] }) {
  const counts = new Map<string, number>(STRIDE_ORDER.map((s) => [s, 0]));
  for (const f of findings) counts.set(strideOf(f), (counts.get(strideOf(f)) ?? 0) + 1);
  const max = Math.max(1, ...counts.values());

  return (
    <Card className="gap-4">
      <CardHeader>
        <CardTitle className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          STRIDE
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5">
        {STRIDE_ORDER.map((s) => {
          const n = counts.get(s) ?? 0;
          return (
            <div key={s} className="grid grid-cols-[128px_1fr_24px] items-center gap-3 font-mono text-xs">
              <span className={n ? "text-muted-foreground" : "text-muted-foreground/40"}>{s}</span>
              <span className="h-1.5 overflow-hidden rounded-full bg-secondary">
                <span
                  className="block h-full rounded-full bg-gradient-to-r from-primary to-[#4d9fff] transition-[width]"
                  style={{ width: `${(n / max) * 100}%` }}
                />
              </span>
              <span className="text-right tabular-nums text-foreground">{n}</span>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
