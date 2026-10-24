from __future__ import annotations

import unittest
from types import MappingProxyType

from autodev.redaction import SECRET_VALUE, sanitize, sanitized_json


class RedactionTests(unittest.TestCase):
    def test_immutable_contract_shapes_are_redacted(self) -> None:
        canary = "IMMUTABLE-CANARY"
        payload = MappingProxyType({"items": (MappingProxyType({"message": canary}),)})
        self.assertNotIn(canary, sanitized_json(payload, (canary,)))
        self.assertEqual(sanitize(payload, (canary,)), {"items": [{"message": SECRET_VALUE}]})

    def test_authorization_values_redacted_without_explicit_canaries(self) -> None:
        for value in ("raw-value", "Basic encoded-value", "Bearer arbitrary-value"):
            with self.subTest(scheme=value.split()[0]):
                result = sanitized_json({"line": f"authorization: {value}"})
                self.assertNotIn(value.split()[-1], result)
                self.assertIn(SECRET_VALUE, result)

    def test_secret_keys_and_canaries_are_removed(self) -> None:
        canary = "AD00-CANARY-SECRET"
        payload = {
            "name": "kept",
            "api_key": "abc123",
            "quoted": "secret = 'space separated value'",
            "nested": {
                "token": "tok_live",
                "message": f"authorization: Bearer {canary}",
                "private_key": "-----BEGIN PRIVATE KEY-----\nline\n-----END PRIVATE KEY-----",
                "url": f"https://user:{canary}@example.invalid/path",
            },
        }
        text = sanitized_json(payload, [canary])
        self.assertIn("kept", text)
        self.assertIn(SECRET_VALUE, text)
        self.assertNotIn("abc123", text)
        self.assertNotIn("tok_live", text)
        self.assertNotIn("space separated value", text)
        self.assertNotIn(canary, text)
        self.assertNotIn("BEGIN PRIVATE KEY", text)

    def test_assignment_forms_are_redacted_without_losing_non_secret_text(self) -> None:
        canary = "explicit-canary-value"
        payload = "operator=visible api_key=123 password:open-sesame Bearer explicit-canary-value"
        redacted = sanitized_json({"line": payload}, [canary])
        self.assertIn("operator=visible", redacted)
        self.assertNotIn("123", redacted)
        self.assertNotIn("open-sesame", redacted)
        self.assertNotIn(canary, redacted)

    def test_bearer_token_redacted_without_explicit_canary(self) -> None:
        redacted = sanitized_json({"line": "authorization: Bearer arbitrary-token-value"})
        self.assertIn("Bearer [REDACTED]", redacted)
        self.assertNotIn("arbitrary-token-value", redacted)

    def test_canaries_in_keys_are_redacted(self) -> None:
        canary = "KEY-CANARY"
        redacted = sanitized_json({f"name-{canary}": "safe"}, [canary])
        self.assertNotIn(canary, redacted)
        self.assertIn("name-[REDACTED]", redacted)

    def test_sanitize_preserves_non_secret_shape(self) -> None:
        result = sanitize({"items": [{"kind": "baseline", "count": 1}]})
        self.assertEqual(result, {"items": [{"kind": "baseline", "count": 1}]})


if __name__ == "__main__":
    unittest.main()
