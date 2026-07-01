"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { getMeta, type Meta } from "@/lib/api";
import { cn } from "@/lib/utils";
import { ShieldCheck, Terminal, LayoutDashboard } from "lucide-react";

export function CommandBar({ active }: { active: "console" | "dashboard" }) {
  const [meta, setMeta] = useState<Meta | null>(null);
  useEffect(() => {
    getMeta().then(setMeta).catch(() => setMeta({ offline: true }));
  }, []);

  const online = meta && !meta.offline;

  return (
    <header className="sticky top-0 z-40 border-b border-border bg-card/60 backdrop-blur-md">
      <div className="mx-auto flex max-w-[1400px] flex-wrap items-center gap-x-6 gap-y-3 px-6 py-3">
        <Link href="/" className="flex items-center gap-3">
          <span className="size-3 rotate-45 bg-primary shadow-[0_0_14px_rgba(53,224,208,0.7)]" />
          <span className="font-mono text-sm font-semibold tracking-tight">
            cyberhackmythos
          </span>
        </Link>

        <nav className="flex items-center gap-1 font-mono text-xs">
          <NavLink href="/" active={active === "console"} icon={<Terminal className="size-3.5" />}>
            Console
          </NavLink>
          <NavLink
            href="/dashboard"
            active={active === "dashboard"}
            icon={<LayoutDashboard className="size-3.5" />}
          >
            Dashboard
          </NavLink>
        </nav>

        <div className="ml-auto flex items-center gap-4 font-mono text-[11px] text-muted-foreground">
          {meta?.model && <span className="hidden sm:inline">{meta.model}</span>}
          {meta?.isolation && (
            <span className="hidden items-center gap-1.5 lg:flex" title="Command sandbox">
              <ShieldCheck className="size-3.5 text-primary" />
              {meta.backend === "docker" ? "docker · network:none" : "subprocess sandbox"}
            </span>
          )}
          <span className="flex items-center gap-1.5">
            <span
              className={cn(
                "size-1.5 rounded-full",
                online ? "bg-primary" : "bg-muted-foreground",
              )}
            />
            {online ? "engine online" : "engine offline"}
          </span>
        </div>
      </div>
    </header>
  );
}

function NavLink({
  href,
  active,
  icon,
  children,
}: {
  href: string;
  active: boolean;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <Link
      href={href}
      className={cn(
        "flex items-center gap-1.5 rounded-md px-3 py-1.5 transition-colors",
        active
          ? "bg-secondary text-foreground"
          : "text-muted-foreground hover:text-foreground",
      )}
    >
      {icon}
      {children}
    </Link>
  );
}
