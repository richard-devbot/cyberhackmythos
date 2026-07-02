"use client";

import { useEffect, useState } from "react";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { getModels, setModel, type ModelOption } from "@/lib/api";
import { toast } from "sonner";
import { Cpu, Loader2, Plug } from "lucide-react";

const CUSTOM = "__custom__";

export function ModelSwitcher() {
  const [models, setModels] = useState<ModelOption[]>([]);
  const [current, setCurrent] = useState("");
  const [busy, setBusy] = useState(false);
  const [customOpen, setCustomOpen] = useState(false);
  const [form, setForm] = useState({ model: "", baseUrl: "", apiKey: "" });

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
    if (value === CUSTOM) {
      setCustomOpen(true);
      return;
    }
    const prev = current;
    setBusy(true);
    setCurrent(value);
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

  const applyCustom = async () => {
    if (!form.model.trim() || !form.baseUrl.trim()) {
      toast.error("Model and Base URL are required");
      return;
    }
    setBusy(true);
    try {
      const r = await setModel(form.model.trim(), form.baseUrl.trim(), form.apiKey.trim() || undefined);
      if (r.ok) {
        setCurrent(form.model.trim());
        setCustomOpen(false);
        toast.success(`Connected to ${form.model.trim()}`);
      } else {
        toast.error(r.error ?? "Connection failed");
      }
    } catch {
      toast.error("Engine offline — start the API");
    } finally {
      setBusy(false);
    }
  };

  if (!current) return null;
  const known = models.some((m) => m.id === current);

  return (
    <>
      <Select value={known ? current : ""} onValueChange={onChange} disabled={busy}>
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
          <span className="max-w-[180px] truncate">{current.split("/").pop()}</span>
        </SelectTrigger>
        <SelectContent className="font-mono text-xs">
          {models.map((m) => (
            <SelectItem key={m.id} value={m.id}>
              {m.label || m.id}
            </SelectItem>
          ))}
          {!known && <SelectItem value={current}>{current} (custom)</SelectItem>}
          <SelectItem value={CUSTOM}>
            <span className="flex items-center gap-1.5">
              <Plug className="size-3" /> Custom endpoint…
            </span>
          </SelectItem>
        </SelectContent>
      </Select>

      <Dialog open={customOpen} onOpenChange={setCustomOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm">Custom model endpoint</DialogTitle>
            <DialogDescription className="text-xs">
              Point at any OpenAI-compatible endpoint — e.g. a Colab-tunneled WhiteRabbitNeo or
              OpenMythos (see <code>colab/serve_security_model.ipynb</code>).
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3 py-2">
            <Field label="Model" placeholder="monotykamary/whiterabbitneo-v1.5a"
              value={form.model} onChange={(v) => setForm({ ...form, model: v })} />
            <Field label="Base URL" placeholder="https://xxxx.trycloudflare.com/v1"
              value={form.baseUrl} onChange={(v) => setForm({ ...form, baseUrl: v })} />
            <Field label="API key (optional)" placeholder="ollama"
              value={form.apiKey} onChange={(v) => setForm({ ...form, apiKey: v })} />
          </div>
          <DialogFooter>
            <Button variant="secondary" size="sm" onClick={() => setCustomOpen(false)}>Cancel</Button>
            <Button size="sm" onClick={applyCustom} disabled={busy} className="gap-2">
              {busy && <Loader2 className="size-3.5 animate-spin" />} Connect
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function Field({
  label, placeholder, value, onChange,
}: {
  label: string;
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="space-y-1.5">
      <Label className="font-mono text-[11px] text-muted-foreground">{label}</Label>
      <Input
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className="font-mono text-xs"
      />
    </div>
  );
}
