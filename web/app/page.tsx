"use client";

import { CommandBar } from "@/components/dashboard/command-bar";
import { KpiStrip } from "@/components/dashboard/kpi-strip";
import { SeverityRing } from "@/components/dashboard/severity-ring";
import { StridePanel } from "@/components/dashboard/stride-panel";
import { RiskHotspots } from "@/components/dashboard/risk-hotspots";
import { FindingsTable } from "@/components/dashboard/findings-table";
import { MOCK_FINDINGS, MOCK_META } from "@/lib/mock";

export default function Home() {
  const findings = MOCK_FINDINGS;

  return (
    <div className="flex min-h-full flex-col">
      <CommandBar meta={MOCK_META} />

      <main className="mx-auto w-full max-w-[1400px] flex-1 space-y-4 px-6 py-6">
        <div className="flex items-baseline justify-between">
          <h1 className="text-lg font-semibold tracking-tight">Audit overview</h1>
          <p className="font-mono text-xs text-muted-foreground">
            scanned {MOCK_META.scannedAt} · showing demo data
          </p>
        </div>

        <KpiStrip findings={findings} />

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <SeverityRing findings={findings} />
          <StridePanel findings={findings} />
          <RiskHotspots findings={findings} />
        </div>

        <FindingsTable findings={findings} />
      </main>

      <footer className="border-t border-border py-4 text-center font-mono text-[11px] text-muted-foreground">
        cyberhackmythos · real scanners · live threat intel · verified patches
      </footer>
    </div>
  );
}
