"""Local-only, allowlisted Preview server. No backend, database, or extra packages."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

PREVIEW = Path(__file__).resolve().parent
REPOSITORY = PREVIEW.parents[2]
ASSETS = REPOSITORY / "src/incident_awareness/dashboard/ui/assets"
PREVIEW_URL = "/tests/dashboard/preview/telemetry-preview.html"
ASSET_NAMES = (
    "dashboard-shell.css",
    "dashboard.css",
    "dashboard-telemetry-contract.mjs",
    "dashboard-telemetry-chart.mjs",
    "dashboard-telemetry-controller.mjs",
)
ROUTES = {
    f"/tests/dashboard/preview/{name}": PREVIEW / name
    for name in (
        "telemetry-preview.html",
        "telemetry-preview.css",
        "telemetry-preview.mjs",
        "telemetry-preview-model.mjs",
    )
}
ROUTES.update({f"/dashboard-assets/{name}": ASSETS / name for name in ASSET_NAMES})
# The generator's relative import also works unmodified in Node contract tests.
ROUTES.update(
    {f"/src/incident_awareness/dashboard/ui/assets/{name}": ASSETS / name for name in ASSET_NAMES}
)


class PreviewHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/":
            self.send_response(302)
            self.send_header("Location", PREVIEW_URL)
            self.end_headers()
            return
        target = ROUTES.get(path)
        if target is None:
            self.send_error(404)
            return
        content = target.read_bytes()
        content_type = {
            ".html": "text/html",
            ".css": "text/css",
            ".mjs": "text/javascript",
        }[target.suffix]
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(content)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    with ThreadingHTTPServer(("127.0.0.1", args.port), PreviewHandler) as server:
        print(f"Local synthetic Preview: http://127.0.0.1:{args.port}/", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
