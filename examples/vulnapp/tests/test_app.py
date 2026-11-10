import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app  # noqa: E402


class AppTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = app.make_server(0)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def get(self, path, headers=None):
        req = urllib.request.Request(self.base + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_health(self):
        self.assertEqual(self.get("/health")[0], 200)

    def test_public_file(self):
        status, body = self.get("/files?name=hello.txt")
        self.assertEqual(status, 200)
        self.assertIn(b"hello", body)

    def test_admin_users_needs_token(self):
        self.assertEqual(self.get("/admin/users")[0], 403)
        status, body = self.get("/admin/users", {"X-Admin-Token": app.ADMIN_TOKEN})
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)), 2)


if __name__ == "__main__":
    unittest.main()
