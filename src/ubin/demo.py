from __future__ import annotations

from email import policy
from email.parser import BytesParser
import hashlib
import html
import math
import os
from pathlib import Path
import shutil
import tempfile
import threading
import uuid
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import ubin
from ubin.secure import SecureServer, generate_localhost_certificate

RUN_ROOT = Path(tempfile.mkdtemp(prefix="ubin-v1-demo-"))
MAX_UPLOAD_BYTES = 64 * 1024 * 1024


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def _server_once(server, result):
    try:
        result["receipt"] = server.serve_once()
    except Exception as exc:
        result["error"] = exc


def _frame_size(size: int) -> int:
    if size <= 0:
        return 64 * 1024
    if size < 6:
        return 1
    return max(1, min(64 * 1024, size // 6))


def _network_demo(source: Path) -> dict:
    run = RUN_ROOT / uuid.uuid4().hex
    run.mkdir(parents=True)
    cert = run / "localhost-cert.pem"
    key = run / "localhost-key.pem"
    out_dir = run / "received"
    client_state = run / "client-state"
    generate_localhost_certificate(cert, key)

    frame_size = _frame_size(source.stat().st_size)
    frame_count = 0 if source.stat().st_size == 0 else math.ceil(source.stat().st_size / frame_size)
    interrupt_after = min(3, frame_count - 1) if frame_count > 1 else None

    server = SecureServer(
        host="127.0.0.1",
        port=0,
        certfile=cert,
        keyfile=key,
        output_dir=out_dir,
        _interrupt_once_after_frames=interrupt_after,
    )

    first_result = {}
    first_thread = threading.Thread(target=_server_once, args=(server, first_result), daemon=True)
    first_thread.start()
    interrupted = False
    try:
        first_sent = ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
            frame_size=frame_size,
            resume=True,
            permutation=True,
            state_dir=client_state,
        )
    except Exception:
        interrupted = True
        first_sent = None
    first_thread.join(timeout=15)

    if interrupted:
        second_result = {}
        second_thread = threading.Thread(target=_server_once, args=(server, second_result), daemon=True)
        second_thread.start()
        sent = ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
            frame_size=frame_size,
            resume=True,
            permutation=True,
            state_dir=client_state,
        )
        second_thread.join(timeout=15)
        server.close()
        if "error" in second_result:
            raise second_result["error"]
        received_receipt = second_result["receipt"]
    else:
        server.close()
        if "error" in first_result:
            raise first_result["error"]
        sent = first_sent
        received_receipt = first_result["receipt"]

    received = out_dir / source.name
    return {
        "interrupted": interrupted,
        "resumed_from": getattr(sent, "resumed_from_frame", 0),
        "frames_sent": getattr(sent, "frames_sent_this_attempt", sent.frame_count),
        "frames": sent.frame_count,
        "tls": sent.tls_version,
        "layout": getattr(sent, "layout", "krp"),
        "sender_sha256": sent.sha256,
        "receiver_sha256": received_receipt.sha256,
        "match": received.exists() and _sha256(source) == _sha256(received) == sent.sha256,
        "no_key": not hasattr(sent, "key"),
        "no_krp_key": not hasattr(sent, "permutation_key"),
        "final_published": received.exists(),
    }


def _image_demo(source: Path, passphrase: str) -> dict:
    run = RUN_ROOT / uuid.uuid4().hex
    run.mkdir(parents=True)
    image = run / f"{source.name}.ubin.png"
    restored = run / f"restored-{source.name}"
    packed = ubin.to_image(source, image, passphrase=passphrase)
    unpacked = ubin.from_image(image, restored, passphrase=passphrase)
    return {
        "run": run.name,
        "image": image.name,
        "restored": restored.name,
        "source": source.name,
        "original_size": packed.original_size,
        "carrier_size": packed.carrier_size,
        "width": packed.width,
        "height": packed.height,
        "sha256": packed.sha256,
        "restored_sha256": unpacked.sha256,
        "match": source.read_bytes() == restored.read_bytes(),
    }


CSS = """
:root{--bg:#07111f;--panel:#0d1b2a;--line:#203a55;--text:#eef7ff;--muted:#96aabd;--a:#5dc7ff;--g:#50e3a4;--bad:#ff6f80}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,rgba(93,199,255,.15),transparent 35%),var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{max-width:1100px;margin:auto;padding:30px 20px 60px}.brand{font-size:30px;font-weight:900;letter-spacing:.08em}.ver{color:var(--a)}.hero,.card{background:rgba(13,27,42,.94);border:1px solid var(--line);border-radius:20px}.hero{padding:30px;margin-top:22px}.card{padding:22px}h1{font-size:42px;margin:0 0 12px}.lead,p{color:var(--muted);line-height:1.6}.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:20px}button,.btn{border:0;border-radius:12px;padding:12px 17px;background:var(--a);color:#04111d;font-weight:850;cursor:pointer;text-decoration:none;display:inline-block}input{width:100%;margin:8px 0 14px;padding:12px;border-radius:10px;border:1px solid var(--line);background:#081827;color:var(--text)}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:20px}.m{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px}.l{font-size:11px;text-transform:uppercase;color:var(--muted);letter-spacing:.08em}.v{font-weight:850;margin-top:6px;word-break:break-all}.good{color:var(--g)}.bad{color:var(--bad)}.hash{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.error{padding:18px;background:#35141b;border:1px solid #74303e;border-radius:14px;color:#ffd8dd;margin-top:20px}.footer{text-align:center;color:#5f788d;margin-top:30px;font-size:12px}@media(max-width:760px){.grid,.metrics{grid-template-columns:1fr}h1{font-size:32px}}
"""


def _page(body: str, title="UBIN v1.0.3 Demo") -> bytes:
    return f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{html.escape(title)}</title><style>{CSS}</style></head><body><div class="wrap"><div class="brand">UBIN <span class="ver">v1.0.3</span></div>{body}<div class="footer">UBIN handles the bytes. You handle the logic. • Local demo only</div></div></body></html>'''.encode()


def _home(message=""):
    extra = f'<div class="error">{html.escape(message)}</div>' if message else ""
    return _page(f'''
<div class="hero"><h1>One library for arbitrary bytes, secure transfer, resume, KRP and a lossless PNG carrier.</h1><div class="lead">This demo runs the actual UBIN v1 APIs locally. No cloud service is required.</div></div>{extra}
<div class="grid">
<div class="card"><h2>Network + Resume + KRP</h2><p>Create a generated multi-frame file, intentionally interrupt the first TLS connection, resume from the durable checkpoint, and prove exact restoration.</p><form method="post" action="/network"><button>Run Network Demo</button></form></div>
<div class="card"><h2>Final PNG Image Carrier</h2><p>Create one encrypted PNG carrier, reverse it, authenticate it, and restore the exact original bytes.</p><form method="post" action="/image"><input name="passphrase" type="password" minlength="8" value="UBIN-Demo-2026" required><button>Run Image Carrier Demo</button></form></div>
</div>
<div class="card" style="margin-top:18px"><h2>Try your own file in the image carrier</h2><p>Browser-demo upload cap: 64 MB. This is a UI limit, not the UBIN core file-size model.</p><form method="post" action="/upload" enctype="multipart/form-data"><input type="file" name="file" required><input name="passphrase" type="password" minlength="8" placeholder="Passphrase (8+ characters)" required><button>Create + Restore PNG Carrier</button></form></div>
''')


def _network_result(r):
    return _page(f'''
<div class="hero"><h1 class="{'good' if r['match'] else 'bad'}">Network demonstration {'passed' if r['match'] else 'failed'}</h1><div class="lead">The first connection was deliberately interrupted when possible, then UBIN resumed using the authenticated KRP path.</div></div>
<div class="metrics">
<div class="m"><div class="l">TLS</div><div class="v good">{html.escape(r['tls'])}</div></div>
<div class="m"><div class="l">Layout</div><div class="v good">{html.escape(r['layout'])}</div></div>
<div class="m"><div class="l">Interrupted</div><div class="v">{r['interrupted']}</div></div>
<div class="m"><div class="l">Resumed from</div><div class="v">Frame {r['resumed_from']}</div></div>
<div class="m"><div class="l">Frames final attempt</div><div class="v">{r['frames_sent']} / {r['frames']}</div></div>
<div class="m"><div class="l">Exact match</div><div class="v good">{r['match']}</div></div>
<div class="m"><div class="l">AES key exposed</div><div class="v good">{'NO' if r['no_key'] else 'YES'}</div></div>
<div class="m"><div class="l">KRP key exposed</div><div class="v good">{'NO' if r['no_krp_key'] else 'YES'}</div></div>
<div class="m"><div class="l">Final published</div><div class="v good">{r['final_published']}</div></div>
</div><div class="grid"><div class="card"><h2>Sender SHA-256</h2><div class="hash">{r['sender_sha256']}</div></div><div class="card"><h2>Receiver SHA-256</h2><div class="hash">{r['receiver_sha256']}</div></div></div><p><a class="btn" href="/">Back</a></p>
''')


def _image_result(r):
    query = urllib.parse.urlencode({"run": r["run"], "file": r["image"]})
    return _page(f'''
<div class="hero"><h1 class="{'good' if r['match'] else 'bad'}">PNG carrier {'verified' if r['match'] else 'failed'}</h1><div class="lead">The source was authenticated, encrypted, KRP-arranged, encoded as one lossless PNG, decoded, reversed and restored.</div></div>
<div class="metrics">
<div class="m"><div class="l">Source</div><div class="v">{html.escape(r['source'])}</div></div>
<div class="m"><div class="l">Original size</div><div class="v">{r['original_size']:,}</div></div>
<div class="m"><div class="l">PNG size</div><div class="v">{r['carrier_size']:,}</div></div>
<div class="m"><div class="l">Dimensions</div><div class="v">{r['width']} × {r['height']}</div></div>
<div class="m"><div class="l">Exact match</div><div class="v good">{r['match']}</div></div>
<div class="m"><div class="l">Format</div><div class="v good">PNG / KRP / AES-GCM</div></div>
</div><div class="grid"><div class="card"><h2>Original SHA-256</h2><div class="hash">{r['sha256']}</div></div><div class="card"><h2>Restored SHA-256</h2><div class="hash">{r['restored_sha256']}</div></div></div><p><a class="btn" href="/download?{query}">Download Encrypted PNG</a> <a class="btn" href="/">Back</a></p>
''')


def _multipart(headers, body):
    content_type = headers.get("Content-Type", "")
    envelope = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
    msg = BytesParser(policy=policy.default).parsebytes(envelope)
    result = {}
    if not msg.is_multipart():
        return result
    for part in msg.iter_parts():
        if part.get_content_disposition() != "form-data":
            continue
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        data = part.get_payload(decode=True) or b""
        filename = part.get_filename()
        result[name] = (filename, data) if filename is not None else data.decode(errors="replace")
    return result


def _safe_name(name):
    name = Path((name or "").replace("\\", "/")).name
    cleaned = "".join(c for c in name if c.isalnum() or c in "._- ()").strip(" .")
    return cleaned or "uploaded.bin"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[UBIN demo]", fmt % args)

    def _html(self, payload, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self._html(_home())
            return
        if parsed.path == "/download":
            q = urllib.parse.parse_qs(parsed.query)
            run = (q.get("run") or [""])[0]
            name = _safe_name((q.get("file") or [""])[0])
            path = RUN_ROOT / run / name
            if not run.isalnum() or not path.is_file():
                self.send_error(404)
                return
            data = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_error(404)

    def do_POST(self):
        try:
            if self.path == "/network":
                run = RUN_ROOT / f"source-{uuid.uuid4().hex}"
                run.mkdir(parents=True)
                source = run / "ubin_network_demo.futureXYZ"
                source.write_bytes(os.urandom(64 * 1024 * 6 + 123))
                self._html(_network_result(_network_demo(source)))
                return

            raw_len = int(self.headers.get("Content-Length", "0"))
            if raw_len > MAX_UPLOAD_BYTES + 1024 * 1024:
                self._html(_home("Upload is over the 64 MB browser-demo cap."), 413)
                return
            body = self.rfile.read(raw_len)

            if self.path == "/image":
                fields = urllib.parse.parse_qs(body.decode())
                passphrase = (fields.get("passphrase") or [""])[0]
                run = RUN_ROOT / f"source-{uuid.uuid4().hex}"
                run.mkdir(parents=True)
                source = run / "ubin_image_demo.futureXYZ"
                source.write_bytes(os.urandom(300_123))
                self._html(_image_result(_image_demo(source, passphrase)))
                return

            if self.path == "/upload":
                fields = _multipart(self.headers, body)
                upload = fields.get("file")
                passphrase = fields.get("passphrase", "")
                if not upload:
                    self._html(_home("Choose a file."), 400)
                    return
                filename, data = upload
                if len(data) > MAX_UPLOAD_BYTES:
                    self._html(_home("Upload is over the 64 MB browser-demo cap."), 413)
                    return
                run = RUN_ROOT / f"source-{uuid.uuid4().hex}"
                run.mkdir(parents=True)
                source = run / _safe_name(filename)
                source.write_bytes(data)
                self._html(_image_result(_image_demo(source, passphrase)))
                return

            self.send_error(404)
        except Exception as exc:
            self._html(_page(f'<div class="hero"><h1 class="bad">Demo rejected</h1></div><div class="error">{html.escape(type(exc).__name__)}: {html.escape(str(exc))}</div><p><a class="btn" href="/">Back</a></p>'), 500)


def run_demo(*, port=5055, open_browser=True):
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    url = f"http://127.0.0.1:{port}"
    print(f"UBIN v1.0.3 demo: {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        shutil.rmtree(RUN_ROOT, ignore_errors=True)


def main():
    run_demo()


if __name__ == "__main__":
    main()
