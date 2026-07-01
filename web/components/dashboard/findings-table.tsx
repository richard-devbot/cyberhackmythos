"use client";

import { useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { Finding, Priority } from "@/lib/types";
import { CATEGORY_META, PRIORITY_META, SEV_META, rankFindings } from "@/lib/severity";

type Filter = "all" | Priority;

function SeverityCell({ f }: { f: Finding }) {
  const m = SEV_META[f.severity];
  return (
    <span className="inline-flex items-center gap-2 font-mono text-xs font-semibold" style={{ color: m.color }}>
      <span aria-hidden>{m.shape}</span>
      <span>{m.label.toUpperCase()}</span>
    </span>
  );
}

function PriorityBadge({ p }: { p?: Priority | null }) {
  if (!p) return <span className="text-muted-foreground">—</span>;
  const m = PRIORITY_META[p];
  return (
    <span
      className="inline-block rounded-sm px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider"
      style={{ background: m.color, color: "#07110d" }}
    >
      {m.label}
    </span>
  );
}

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [filter, setFilter] = useState<Filter>("all");

  const counts = {
    all: findings.length,
    act_now: findings.filter((f) => f.priority === "act_now").length,
    attend: findings.filter((f) => f.priority === "attend").length,
    track: findings.filter((f) => f.priority === "track").length,
  };

  const rows = useMemo(() => {
    const filtered = filter === "all" ? findings : findings.filter((f) => f.priority === filter);
    return rankFindings(filtered);
  }, [findings, filter]);

  return (
    <Card className="gap-4">
      <CardHeader className="flex-row items-center justify-between gap-4 space-y-0">
        <CardTitle className="font-mono text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
          Findings
        </CardTitle>
        <Tabs value={filter} onValueChange={(v) => setFilter(v as Filter)}>
          <TabsList className="h-8 bg-secondary font-mono text-xs">
            <TabsTrigger value="all" className="text-xs">All · {counts.all}</TabsTrigger>
            <TabsTrigger value="act_now" className="text-xs">Act now · {counts.act_now}</TabsTrigger>
            <TabsTrigger value="attend" className="text-xs">Attend · {counts.attend}</TabsTrigger>
            <TabsTrigger value="track" className="text-xs">Track · {counts.track}</TabsTrigger>
          </TabsList>
        </Tabs>
      </CardHeader>
      <CardContent>
        <div className="cm-scroll overflow-x-auto">
          <Table className="min-w-[860px]">
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                {["Priority", "Severity", "CVSS", "EPSS", "KEV", "Cat", "Finding", "Location", "Tool"].map((h) => (
                  <TableHead key={h} className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                    {h}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((f, i) => (
                <TableRow
                  key={`${f.tool}-${f.rule_id}-${f.file}-${f.line}-${i}`}
                  style={{ boxShadow: `inset 3px 0 0 ${SEV_META[f.severity].color}` }}
                >
                  <TableCell><PriorityBadge p={f.priority} /></TableCell>
                  <TableCell><SeverityCell f={f} /></TableCell>
                  <TableCell className="font-mono tabular-nums text-foreground/80">
                    {f.cvss_score != null ? f.cvss_score.toFixed(1) : "—"}
                  </TableCell>
                  <TableCell className="font-mono tabular-nums text-foreground/80">
                    {f.epss != null ? `${Math.round(f.epss * 100)}%` : "—"}
                  </TableCell>
                  <TableCell>
                    {f.kev ? (
                      <Tooltip>
                        <TooltipTrigger
                          render={
                            <span className="cm-kev-pulse inline-block rounded-sm bg-[#ff4d5e] px-1.5 py-0.5 font-mono text-[9px] font-bold text-[#120406]" />
                          }
                        >
                          KEV
                        </TooltipTrigger>
                        <TooltipContent className="font-mono text-xs">
                          On CISA KEV — actively exploited{f.kev_ransomware ? " · ransomware" : ""}
                        </TooltipContent>
                      </Tooltip>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <Tooltip>
                      <TooltipTrigger
                        render={
                          <span className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] tracking-wide text-muted-foreground" />
                        }
                      >
                        {CATEGORY_META[f.category].tag}
                      </TooltipTrigger>
                      <TooltipContent className="font-mono text-xs">{CATEGORY_META[f.category].label}</TooltipContent>
                    </Tooltip>
                  </TableCell>
                  <TableCell className="max-w-[340px]">
                    <div className="truncate text-sm text-foreground/90" title={f.title}>{f.title}</div>
                    <div className="truncate font-mono text-[10px] text-muted-foreground">
                      {[...(f.cwe ?? []).slice(0, 2), f.cve].filter(Boolean).join(" · ")}
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-[11px] text-[#8fa6cf]">
                    {f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : "—"}
                  </TableCell>
                  <TableCell className="font-mono text-[11px] text-muted-foreground">{f.tool}</TableCell>
                </TableRow>
              ))}
              {rows.length === 0 && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={9} className="py-10 text-center font-mono text-xs text-muted-foreground">
                    No findings in this lane.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}
