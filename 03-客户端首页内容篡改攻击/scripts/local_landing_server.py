#!/usr/bin/env python3
"""仅用于授权测试：提供本机落地页，验证篡改页面的外跳能力。"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import os


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (
            "<!doctype html><meta charset='utf-8'>"
            "<title>Homewoo Security Lab</title>"
            "<h1>LOCAL_TEST_LANDING</h1>"
            "<p>仅用于授权安全测试，未连接生产服务。</p>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        evidence_file = os.environ.get("LANDING_EVIDENCE_FILE")
        if evidence_file:
            with open(evidence_file, "a", encoding="utf-8") as handle:
                handle.write(f"LOCAL_TEST_LANDING {self.path}\n")

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    print("LOCAL_LANDING_LISTENING=127.0.0.1:18080", flush=True)
    HTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
