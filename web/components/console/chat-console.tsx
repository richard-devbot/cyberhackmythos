"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Button } from "@/components/ui/button";
import { streamChat, type AgentEvent } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  ChevronRight, Loader2, Send, Square, Terminal, Wrench, BrainCircuit, ShieldCheck, ShieldAlert,
} from "lucide-react";

type Item =
  | { id: number; role: "user"; text: string }
  | { id: number; role: "assistant"; kind: "text"; text: string }
  | { id: number; role: "assistant"; kind: "thinking"; text: string; active: boolean }
  | { id: number; role: "assistant"; kind: "error"; text: string }
  | {
      id: number; role: "assistant"; kind: "tool";
      name: string; args: string; output: string; running: boolean;
    };

const SUGGESTIONS = [
  "Audit this repo for vulnerabilities and prioritize by exploitability.",
  "Scan the workspace with all scanners, then enrich CVEs with EPSS and KEV.",
  "Find hardcoded secrets and propose a verified fix.",
];

export function ChatConsole({ sessionId }: { sessionId: string }) {
  const [items, setItems] = useState<Item[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const idRef = useRef(0);
  const textRef = useRef<number | null>(null);
  const toolRef = useRef<number | null>(null);
  const thinkRef = useRef<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  const nextId = () => ++idRef.current;

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [items]);

  const patch = useCallback((id: number, fn: (it: Item) => Item) => {
    setItems((prev) => prev.map((it) => (it.id === id ? fn(it) : it)));
  }, []);

  const handleEvent = useCallback(
    (ev: AgentEvent) => {
      if (ev.type === "reasoning") {
        if (thinkRef.current == null) {
          const id = nextId();
          thinkRef.current = id;
          setItems((p) => [...p, { id, role: "assistant", kind: "thinking", text: "", active: true }]);
        }
        const id = thinkRef.current;
        patch(id, (it) => (it.role === "assistant" && it.kind ==="thinking" ? { ...it, text: it.text + ev.content } : it));
      } else if (ev.type === "text") {
        if (thinkRef.current != null) {
          patch(thinkRef.current, (it) => (it.role === "assistant" && it.kind ==="thinking" ? { ...it, active: false } : it));
          thinkRef.current = null;
        }
        if (textRef.current == null) {
          const id = nextId();
          textRef.current = id;
          setItems((p) => [...p, { id, role: "assistant", kind: "text", text: ev.content }]);
        } else {
          patch(textRef.current, (it) => (it.role === "assistant" && it.kind ==="text" ? { ...it, text: it.text + ev.content } : it));
        }
      } else if (ev.type === "tool_call") {
        textRef.current = null;
        thinkRef.current = null;
        const id = nextId();
        toolRef.current = id;
        setItems((p) => [
          ...p,
          { id, role: "assistant", kind: "tool", name: ev.name, args: ev.arguments, output: "", running: true },
        ]);
      } else if (ev.type === "tool_output") {
        const id = toolRef.current;
        if (id != null) {
          patch(id, (it) =>
            it.role === "assistant" && it.kind ==="tool" ? { ...it, output: ev.content, running: !!ev.partial } : it,
          );
          if (!ev.partial) toolRef.current = null;
        }
      } else if (ev.type === "error") {
        setItems((p) => [...p, { id: nextId(), role: "assistant", kind: "error", text: ev.content }]);
      } else if (ev.type === "done" || ev.type === "end") {
        setStreaming(false);
      }
    },
    [patch],
  );

  const send = useCallback(
    async (message: string) => {
      const msg = message.trim();
      if (!msg || streaming) return;
      setInput("");
      setItems((p) => [...p, { id: nextId(), role: "user", text: msg }]);
      textRef.current = null;
      toolRef.current = null;
      thinkRef.current = null;
      setStreaming(true);
      const ctrl = new AbortController();
      abortRef.current = ctrl;
      try {
        await streamChat(sessionId, msg, handleEvent, ctrl.signal);
      } catch (e) {
        if (!ctrl.signal.aborted) {
          setItems((p) => [
            ...p,
            { id: nextId(), role: "assistant", kind: "error", text: String(e) },
          ]);
        }
      } finally {
        setStreaming(false);
      }
    },
    [handleEvent, sessionId, streaming],
  );

  const stop = () => {
    abortRef.current?.abort();
    setStreaming(false);
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div ref={scrollRef} className="cm-scroll min-h-0 flex-1 overflow-y-auto px-4 py-6">
        <div className="mx-auto max-w-3xl space-y-4">
          {items.length === 0 && <EmptyState onPick={send} />}
          {items.map((it) => (
            <MessageItem key={it.id} item={it} />
          ))}
          {streaming && toolRef.current == null && thinkRef.current == null && textRef.current == null && (
            <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
              <Loader2 className="size-3.5 animate-spin" /> working…
            </div>
          )}
        </div>
      </div>

      <div className="border-t border-border bg-card/40 px-4 py-3">
        <div className="mx-auto flex max-w-3xl items-end gap-2">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                send(input);
              }
            }}
            rows={1}
            placeholder="Ask cyberhackmythos to audit code, scan the workspace, or verify a fix…"
            className="max-h-40 min-h-10 flex-1 resize-none rounded-lg border border-border bg-background px-3.5 py-2.5 text-sm outline-none placeholder:text-muted-foreground/70 focus:border-primary/60"
          />
          {streaming ? (
            <Button variant="destructive" size="icon" className="size-10 shrink-0" onClick={stop}>
              <Square className="size-4" />
            </Button>
          ) : (
            <Button size="icon" className="size-10 shrink-0" onClick={() => send(input)} disabled={!input.trim()}>
              <Send className="size-4" />
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

function EmptyState({ onPick }: { onPick: (s: string) => void }) {
  return (
    <div className="flex flex-col items-center gap-6 py-16 text-center">
      <div className="flex items-center gap-3">
        <span className="size-4 rotate-45 bg-primary shadow-[0_0_18px_rgba(53,224,208,0.7)]" />
        <span className="font-mono text-lg font-semibold">cyberhackmythos</span>
      </div>
      <p className="max-w-md font-mono text-sm text-muted-foreground">
        Paste a codebase or point at the workspace. Real scanners, live threat intel,
        verified patches — grounded in evidence, not guesses.
      </p>
      <div className="flex max-w-lg flex-wrap justify-center gap-2">
        {SUGGESTIONS.map((s) => (
          <button
            key={s}
            onClick={() => onPick(s)}
            className="rounded-full border border-border bg-card px-3.5 py-1.5 text-left text-xs text-muted-foreground transition-colors hover:border-primary/50 hover:text-foreground"
          >
            {s}
          </button>
        ))}
      </div>
    </div>
  );
}

function MessageItem({ item }: { item: Item }) {
  if (item.role === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-2xl rounded-br-sm bg-secondary px-4 py-2.5 text-sm">
          {item.text}
        </div>
      </div>
    );
  }
  if (item.kind === "thinking") return <ThinkingBlock text={item.text} active={item.active} />;
  if (item.kind === "tool") return <ToolCard item={item} />;
  if (item.kind === "error") {
    return (
      <div className="flex items-start gap-2 rounded-lg border border-[#ff4d5e]/40 bg-[#ff4d5e]/10 px-3.5 py-2.5 font-mono text-xs text-[#ff8a95]">
        <ShieldAlert className="mt-0.5 size-4 shrink-0" /> {item.text}
      </div>
    );
  }
  return (
    <div className="cm-md max-w-none text-sm leading-relaxed">
      <Markdown remarkPlugins={[remarkGfm]}>{item.text}</Markdown>
    </div>
  );
}

function ThinkingBlock({ text, active }: { text: string; active: boolean }) {
  return (
    <details className="group rounded-lg border border-border/60 bg-card/40" open={active}>
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 font-mono text-xs text-muted-foreground">
        <BrainCircuit className={cn("size-3.5", active && "text-primary")} />
        {active ? (
          <span className="flex items-center gap-1.5">
            Reasoning <Loader2 className="size-3 animate-spin" />
          </span>
        ) : (
          "Reasoning"
        )}
        <ChevronRight className="ml-auto size-3.5 transition-transform group-open:rotate-90" />
      </summary>
      <pre className="cm-scroll max-h-64 overflow-auto whitespace-pre-wrap px-3 pb-3 font-mono text-[11px] leading-relaxed text-muted-foreground/80">
        {text}
      </pre>
    </details>
  );
}

function ToolCard({
  item,
}: {
  item: Extract<Item, { kind: "tool" }>;
}) {
  const isShell = item.name === "shell";
  const verdict =
    item.name === "verify_patch"
      ? item.output.includes("✅ PATCH VERIFIED")
        ? "ok"
        : item.output.includes("❌ PATCH NOT VERIFIED")
          ? "bad"
          : null
      : null;

  return (
    <details className="group overflow-hidden rounded-lg border border-border bg-card" open={item.running}>
      <summary className="flex cursor-pointer list-none items-center gap-2.5 px-3.5 py-2.5 font-mono text-xs">
        {isShell ? <Terminal className="size-3.5 text-primary" /> : <Wrench className="size-3.5 text-primary" />}
        <span className="font-semibold text-foreground">{item.name}</span>
        {verdict === "ok" && (
          <span className="inline-flex items-center gap-1 rounded-sm bg-[#0f2e1f] px-1.5 py-0.5 text-[10px] font-bold text-[#38d9a4]">
            <ShieldCheck className="size-3" /> VERIFIED
          </span>
        )}
        {verdict === "bad" && (
          <span className="inline-flex items-center gap-1 rounded-sm bg-[#3a1416] px-1.5 py-0.5 text-[10px] font-bold text-[#ff7a85]">
            <ShieldAlert className="size-3" /> NOT VERIFIED
          </span>
        )}
        {item.running ? (
          <Loader2 className="size-3.5 animate-spin text-muted-foreground" />
        ) : null}
        <ChevronRight className="ml-auto size-3.5 text-muted-foreground transition-transform group-open:rotate-90" />
      </summary>
      <div className="border-t border-border/60 px-3.5 py-2.5">
        {item.args && item.args !== "{}" && (
          <pre className="cm-scroll mb-2 overflow-x-auto rounded bg-background px-2.5 py-1.5 font-mono text-[11px] text-[#9fb4d8]">
            {item.args}
          </pre>
        )}
        {item.output ? (
          <pre className="cm-scroll max-h-72 overflow-auto whitespace-pre-wrap rounded bg-background px-2.5 py-2 font-mono text-[11px] leading-relaxed text-foreground/80">
            {item.output}
          </pre>
        ) : (
          <span className="font-mono text-[11px] text-muted-foreground">running…</span>
        )}
      </div>
    </details>
  );
}
