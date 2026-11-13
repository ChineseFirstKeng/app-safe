import hashlib
import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("engine_download", Path(__file__).resolve().parents[1]/"scripts/engine_download.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EngineDownloadTests(unittest.TestCase):
    def setUp(self):
        self.data = bytes(range(128)) * 8
        self.requests, self.ignore_range = [], False
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):pass
            def do_GET(self):
                bounds = self.headers["Range"][6:].split("-")
                start, stop = map(int, bounds)
                owner.requests.append(start)
                data = owner.data if owner.ignore_range else owner.data[start:stop+1]
                self.send_response(200 if owner.ignore_range else 206)
                if not owner.ignore_range:self.send_header("Content-Range", f"bytes {start}-{stop}/{len(owner.data)}")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):pass
        self.server = ThreadingHTTPServer(("127.0.0.1",0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.url = f"http://127.0.0.1:{self.server.server_port}/asset"
        self.engine = {"size":len(self.data), "sha256":hashlib.sha256(self.data).hexdigest()}

    def test_resume_ranges_and_whole_digest_before_publish(self):
        archive = self.root/"engine.zip"
        directory = self.root/"engine.zip.chunks"
        directory.mkdir()
        (directory/"state.json").write_text(json.dumps({**self.engine,"chunk_size":256}))
        (directory/"0").write_bytes(self.data[:256])
        calls = []
        module.download(self.engine, archive, 2, 256, resolver=lambda e:(calls.append(True) or self.url))
        self.assertEqual(self.data, archive.read_bytes())
        self.assertNotIn(0,self.requests)
        self.assertEqual(1,len(calls))
        module.download(self.engine,archive,resolver=lambda e:self.fail("complete archive should be reused"))

    def test_wrong_digest_never_publishes_archive(self):
        archive = self.root/"wrong.zip"
        with self.assertRaises(module.DownloadError) as caught:
            module.download({**self.engine,"sha256":"0"*64},archive,2,256,resolver=lambda e:self.url)
        self.assertEqual("download_checksum_mismatch",str(caught.exception))
        self.assertFalse(archive.exists())

    def test_server_ignoring_range_is_rejected(self):
        self.ignore_range = True
        with self.assertRaises(module.DownloadError):
            module.fetch_chunk(self.url,self.root,0,0,255,len(self.data),attempts=1)
        self.assertFalse((self.root/"0").exists())

    def test_unapproved_official_source_and_plain_remote_transport_are_rejected(self):
        with patch.object(module.subprocess, "run") as call:
            with self.assertRaises(module.DownloadError):
                module.resolve_asset({"url":"https://example.invalid/tool.zip"})
            with self.assertRaises(module.DownloadError):
                module.fetch_chunk("http://example.invalid/tool.zip",self.root,0,0,1,2)
            call.assert_not_called()
