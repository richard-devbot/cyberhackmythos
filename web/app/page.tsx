"use client";

import { useMemo } from "react";
import { CommandBar } from "@/components/dashboard/command-bar";
import { ChatConsole } from "@/components/console/chat-console";

export default function ConsolePage() {
  const sessionId = useMemo(
    () => (typeof crypto !== "undefined" && crypto.randomUUID ? crypto.randomUUID() : `s-${Date.now()}`),
    [],
  );

  return (
    <div className="flex min-h-full flex-col">
      <CommandBar active="console" />
      <ChatConsole sessionId={sessionId} />
    </div>
  );
}
