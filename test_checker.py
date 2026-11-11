import unittest
from cyberguard.checker import validate_url


class URLValidationTests(unittest.TestCase):
    def test_accepts_https_url(self):
        parsed = validate_url("https://example.com")
        self.assertEqual(parsed.hostname, "example.com")

    def test_rejects_missing_scheme(self):
        with self.assertRaises(ValueError):
            validate_url("example.com")

    def test_rejects_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            validate_url("ftp://example.com")


if __name__ == "__main__":
    unittest.main()
