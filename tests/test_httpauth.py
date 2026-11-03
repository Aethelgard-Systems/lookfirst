"""#668 P2: HTTP entry needs a token off loopback; wrong/missing bearer → 401."""
import tempfile
import unittest
from pathlib import Path

import anyio

from torwaechter import cli, config as cfg, httpauth

TOKEN = b"t" * 40


async def call(app, headers):
    sent = []
    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}
    async def send(msg):
        sent.append(msg)
    await app({"type": "http", "method": "POST", "path": "/mcp", "headers": headers}, receive, send)
    return sent


async def inner(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


class Guard(unittest.TestCase):
    def status(self, headers):
        return anyio.run(call, httpauth.guard(inner, TOKEN), headers)[0]["status"]

    def test_missing_and_wrong_token_401(self):
        self.assertEqual(self.status([]), 401)
        self.assertEqual(self.status([(b"authorization", b"Bearer " + b"x" * 40)]), 401)
        self.assertEqual(self.status([(b"authorization", TOKEN)]), 401)  # scheme required

    def test_right_token_passes(self):
        self.assertEqual(self.status([(b"authorization", b"Bearer " + TOKEN)]), 200)

    def test_bind_rules(self):
        httpauth.check_bind("127.0.0.1", None)
        httpauth.check_bind("::1", None)
        httpauth.check_bind("0.0.0.0", TOKEN)
        for host in ("0.0.0.0", "192.0.2.10", "example.invalid"):
            with self.assertRaises(httpauth.HttpAuthError):
                httpauth.check_bind(host, None)

    def test_short_or_missing_token_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "tok"
            f.write_text("kurz\n")
            with self.assertRaisesRegex(httpauth.HttpAuthError, "at least"):
                httpauth.load_token(f)
            with self.assertRaisesRegex(httpauth.HttpAuthError, "not readable"):
                httpauth.load_token(Path(d) / "fehlt")
            f.write_text("a" * 40 + "\n")
            self.assertEqual(httpauth.load_token(f), b"a" * 40)


class Serve(unittest.TestCase):
    def test_non_loopback_without_token_refuses_before_upstream(self):
        with tempfile.TemporaryDirectory() as d:
            y = Path(d) / "t.yaml"
            y.write_text('upstreams: {x: {command: "/nonexistent-upstream"}}\n')
            conf = cfg.load(y)
            self.assertIsNone(conf.http_token_file)
            with self.assertRaisesRegex(SystemExit, "needs http.token_file"):
                anyio.run(cli.serve, conf, "http", "0.0.0.0", 8470)

    def test_config_token_path_relative_to_config(self):
        with tempfile.TemporaryDirectory() as d:
            y = Path(d) / "t.yaml"
            y.write_text('upstreams: {x: {command: "c"}}\nhttp: {token_file: "private/tok"}\n')
            self.assertEqual(cfg.load(y).http_token_file, Path(d).resolve() / "private/tok")
            y.write_text('upstreams: {x: {command: "c"}}\nhttp: {token: "inline"}\n')
            with self.assertRaises(cfg.ConfigError):
                cfg.load(y)


if __name__ == "__main__":
    unittest.main()
