"use client";

import { useEffect, useState } from "react";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { getModels, setModel, type ModelOption } from "@/lib/api";
import { toast } from "sonner";
import { Cpu, Loader2 } from "lucide-react";

export function ModelSwitcher() {
  const [models, setModels] = useState<ModelOption[]>([]);
  const [current, setCurrent] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getModels()
      .then((d) => {
        setModels(d.recommended ?? []);
        setCurrent(d.current ?? "");
      })
      .catch(() => setCurrent(""));
  }, []);

  const onChange = async (value: string | null) => {
    if (!value) return;
    const prev = current;
    setBusy(true);
    setCurrent(value); // optimistic
    try {
      const r = await setModel(value);
      if (r.ok) toast.success(`Model switched to ${value.split("/").pop()}`);
      else {
        setCurrent(prev);
        toast.error(r.error ?? "Switch failed");
      }
    } catch {
      setCurrent(prev);
      toast.error("Engine offline — start the API");
    } finally {
      setBusy(false);
    }
  };

  if (!current) return null;
  const known = models.some((m) => m.id === current);

  return (
    <Select value={current} onValueChange={onChange} disabled={busy}>
      <SelectTrigger
        size="sm"
        className="h-8 gap-2 border-border bg-secondary font-mono text-xs"
        aria-label="Active model"
      >
        {busy ? (
          <Loader2 className="size-3.5 animate-spin text-primary" />
        ) : (
          <Cpu className="size-3.5 text-primary" />
        )}
        <SelectValue />
      </SelectTrigger>
      <SelectContent className="font-mono text-xs">
        {models.map((m) => (
          <SelectItem key={m.id} value={m.id}>
            {m.label || m.id}
          </SelectItem>
        ))}
        {!known && <SelectItem value={current}>{current}</SelectItem>}
      </SelectContent>
    </Select>
  );
}
