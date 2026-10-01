"""Small experiment HTTP responder: no filesystem access or directory listing."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"SDN lab service is available\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True)
    args = parser.parse_args()
    HTTPServer((args.bind, 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
