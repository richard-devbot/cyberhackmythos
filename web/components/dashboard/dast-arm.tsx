"use client";

import { useEffect, useState } from "react";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { armDast, getMeta, type Meta } from "@/lib/api";
import { toast } from "sonner";
import { Radio, ShieldAlert } from "lucide-react";

// Shown only when the server has DAST enabled. Arming requires an explicit
// authorization acknowledgment — that's the operator's consent to live-scan.
export function DastArm() {
  const [meta, setMeta] = useState<Meta | null>(null);
  const [open, setOpen] = useState(false);
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);

  const refresh = () => getMeta().then(setMeta).catch(() => setMeta(null));
  useEffect(() => {
    refresh();
  }, []);

  if (!meta?.dast_enabled) return null;
  const armed = !!meta.dast_armed;
  const targets = meta.authorized_targets ?? [];

  const disarm = async () => {
    setBusy(true);
    try {
      await armDast(false);
      toast.success("Live testing disarmed");
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  const arm = async () => {
    setBusy(true);
    try {
      const r = await armDast(true);
      if (r.ok) {
        toast.success("Live testing armed");
        setOpen(false);
        setAck(false);
        await refresh();
      } else toast.error(r.error ?? "Failed to arm");
    } catch {
      toast.error("Engine offline");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button
        onClick={() => (armed ? disarm() : setOpen(true))}
        disabled={busy}
        className={
          "flex items-center gap-1.5 rounded-md border px-2.5 py-1 font-mono text-[11px] transition-colors " +
          (armed
            ? "cm-kev-pulse border-[#ff4d5e]/50 bg-[#ff4d5e]/15 text-[#ff8a95]"
            : "border-border text-muted-foreground hover:text-foreground")
        }
        title={armed ? "Live testing armed — click to disarm" : "Arm live testing"}
      >
        <Radio className="size-3.5" />
        {armed ? "LIVE ARMED" : "Live testing off"}
      </button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 font-mono text-sm">
              <ShieldAlert className="size-4 text-[#ff8a3d]" /> Arm live testing
            </DialogTitle>
            <DialogDescription className="text-xs">
              This enables active scanning of live hosts. It only runs against the
              authorized targets configured on the server:
            </DialogDescription>
          </DialogHeader>
          <ul className="my-2 space-y-1 font-mono text-xs">
            {targets.length ? (
              targets.map((t) => (
                <li key={t} className="rounded bg-secondary px-2 py-1 text-foreground/90">{t}</li>
              ))
            ) : (
              <li className="text-[#ff8a95]">No authorized targets set — scans will be refused.</li>
            )}
          </ul>
          <label className="flex cursor-pointer items-start gap-2 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={ack}
              onChange={(e) => setAck(e.target.checked)}
              className="mt-0.5 accent-primary"
            />
            I confirm I am authorized to run security tests against the hosts listed above.
          </label>
          <DialogFooter>
            <Button variant="secondary" size="sm" onClick={() => setOpen(false)}>Cancel</Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={arm}
              disabled={!ack || busy || targets.length === 0}
            >
              Arm live testing
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
