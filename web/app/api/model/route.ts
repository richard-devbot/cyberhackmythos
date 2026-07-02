const BACKEND = process.env.BACKEND_URL ?? "http://127.0.0.1:8000";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  const body = await req.text();
  try {
    const r = await fetch(`${BACKEND}/api/model`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    return new Response(await r.text(), {
      status: r.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    return Response.json({ ok: false, error: "engine offline" }, { status: 502 });
  }
}
