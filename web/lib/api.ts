import type { Finding } from "./types";

export type AgentEvent =
  | { type: "reasoning"; content: string }
  | { type: "text"; content: string }
  | { type: "tool_call"; name: string; arguments: string }
  | { type: "tool_output"; name: string; arguments: string; content: string; partial?: boolean }
  | { type: "done"; content?: string }
  | { type: "error"; content: string }
  | { type: "end" };

export interface Meta {
  isolation?: string;
  backend?: string;
  scanners?: string[];
  model?: string;
  mcp_enabled?: boolean;
  offline?: boolean;
}

// Reads the SSE stream from the proxy route and dispatches each parsed event.
export async function streamChat(
  sessionId: string,
  message: string,
  onEvent: (e: AgentEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const res = await fetch("/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: sessionId, message }),
    signal,
  });
  if (!res.body) throw new Error("No response stream from backend.");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split("\n\n");
    buffer = chunks.pop() ?? "";
    for (const chunk of chunks) {
      const dataLine = chunk.split("\n").find((l) => l.startsWith("data:"));
      if (!dataLine) continue;
      const payload = dataLine.slice(5).trim();
      if (!payload) continue;
      try {
        onEvent(JSON.parse(payload) as AgentEvent);
      } catch {
        // ignore malformed keep-alive lines
      }
    }
  }
}

export async function getFindings(): Promise<{
  findings: Finding[];
  summary: Record<string, number>;
  offline?: boolean;
}> {
  const r = await fetch("/api/findings", { cache: "no-store" });
  return r.json();
}

export async function getMeta(): Promise<Meta> {
  const r = await fetch("/api/meta", { cache: "no-store" });
  return r.json();
}

export interface ModelOption {
  id: string;
  label: string;
  note?: string;
}

export async function getModels(): Promise<{ current: string; recommended: ModelOption[] }> {
  const r = await fetch("/api/models", { cache: "no-store" });
  return r.json();
}

export async function setModel(
  model: string,
  base_url?: string,
  api_key?: string,
): Promise<{ ok: boolean; model?: string; error?: string }> {
  const r = await fetch("/api/model", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model, base_url, api_key }),
  });
  return r.json();
}
