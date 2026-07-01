"use client";

import { useCallback, useEffect, useState } from "react";
import { CommandBar } from "@/components/dashboard/command-bar";
import { KpiStrip } from "@/components/dashboard/kpi-strip";
import { SeverityRing } from "@/components/dashboard/severity-ring";
import { StridePanel } from "@/components/dashboard/stride-panel";
import { RiskHotspots } from "@/components/dashboard/risk-hotspots";
import { FindingsTable } from "@/components/dashboard/findings-table";
import { Button } from "@/components/ui/button";
import { getFindings } from "@/lib/api";
import type { Finding } from "@/lib/types";
import { Loader2, RefreshCw } from "lucide-react";

export default function DashboardPage() {
  const [findings, setFindings] = useState<Finding[] | null>(null);
  const [offline, setOffline] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const d = await getFindings();
      setFindings(d.findings ?? []);
      setOffline(!!d.offline);
    } catch {
      setFindings([]);
      setOffline(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Always render real data — never fabricated findings. Offline/empty get honest states.
  const shown = findings ?? [];
  const banner = offline
    ? "Engine offline — start the API (python api.py) to load live findings."
    : !loading && shown.length === 0
      ? "No findings yet — run a scan from the Console, then refresh."
      : null;

  return (
    <div className="flex min-h-full flex-col">
      <CommandBar active="dashboard" />

      <main className="mx-auto w-full max-w-[1400px] flex-1 space-y-4 px-6 py-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold tracking-tight">Audit overview</h1>
            {banner && <p className="mt-0.5 font-mono text-xs text-muted-foreground">{banner}</p>}
          </div>
          <Button variant="secondary" size="sm" className="gap-2 font-mono text-xs" onClick={load} disabled={loading}>
            {loading ? <Loader2 className="size-3.5 animate-spin" /> : <RefreshCw className="size-3.5" />}
            Refresh
          </Button>
        </div>

        <KpiStrip findings={shown} />

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <SeverityRing findings={shown} />
          <StridePanel findings={shown} />
          <RiskHotspots findings={shown} />
        </div>

        <FindingsTable findings={shown} />
      </main>
    </div>
  );
}
