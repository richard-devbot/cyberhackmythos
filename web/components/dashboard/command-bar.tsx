"use client";

import { Button } from "@/components/ui/button";
import type { ScanMeta } from "@/lib/types";
import { RefreshCw, ShieldCheck } from "lucide-react";

export function CommandBar({ meta }: { meta: ScanMeta }) {
  return (
    <header className="border-b border-border bg-card/40 backdrop-blur-sm">
      <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-x-6 gap-y-3 px-6 py-3.5">
        <div className="flex items-center gap-3">
          <span className="size-3 rotate-45 bg-primary shadow-[0_0_14px_rgba(53,224,208,0.7)]" />
          <span className="font-mono text-sm font-semibold tracking-tight">
            cyberhackmythos<span className="text-muted-foreground"> · security console</span>
          </span>
        </div>

        <div className="hidden items-center gap-2 font-mono text-xs text-muted-foreground md:flex">
          <span className="text-foreground/70">target</span>
          <code className="rounded bg-secondary px-2 py-1 text-foreground/90">{meta.target}</code>
        </div>

        <div className="ml-auto flex items-center gap-4">
          <div className="hidden items-center gap-1.5 font-mono text-[11px] text-muted-foreground lg:flex">
            <ShieldCheck className="size-3.5 text-primary" />
            {meta.isolation}
          </div>
          <div className="hidden items-center gap-1 sm:flex">
            {meta.scanners.map((s) => (
              <span
                key={s}
                className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground"
              >
                {s}
              </span>
            ))}
          </div>
          <Button size="sm" className="gap-2 font-mono text-xs">
            <RefreshCw className="size-3.5" />
            Re-scan
          </Button>
        </div>
      </div>
    </header>
  );
}
