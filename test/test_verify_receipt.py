"""Offline verdict regressions; backend stubs never contact an issuer."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "examples" / "verify_receipt.py"
SPEC = importlib.util.spec_from_file_location("receipt_verifier", SOURCE)
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


class ReceiptVerdictTests(unittest.TestCase):
    def receipt(self):
        receipt = {
            "receipt_type": "offline-test",
            "issued_by": "https://example.invalid",
            "agent_name": "test-agent",
            "signed": True,
            "public_key_b64": "synthetic-key",
            "signature": "synthetic-signature",
        }
        receipt["canonical"] = verifier.rebuild_canonical(receipt)
        receipt["payload_sha256"] = verifier.sha256_hex(receipt["canonical"])
        return receipt

    def verify_with_backend(self, status, receipt=None):
        with patch.object(verifier, "_verify_ed25519", return_value=status):
            return verifier.verify_receipt(
                self.receipt() if receipt is None else receipt,
                expected_public_key_b64="synthetic-key",
            )

    def test_unavailable_verification_is_not_a_signed_success(self):
        result = self.verify_with_backend(
            {"checked": False, "ok": None, "reason": "no local verification backend"}
        )
        self.assertTrue(result["hash_ok"])
        self.assertEqual(result["verdict"], "BAD_SIGNATURE")
        self.assertIs(result["signature_checked"], False)
        self.assertIsNone(result["signature_ok"])

    def test_an_unchecked_ok_flag_is_insufficient(self):
        result = self.verify_with_backend({"checked": False, "ok": True})
        self.assertEqual(result["verdict"], "BAD_SIGNATURE")

    def test_a_checked_but_unknown_result_is_insufficient(self):
        result = self.verify_with_backend({"checked": True, "ok": None})
        self.assertEqual(result["verdict"], "BAD_SIGNATURE")

    def test_checked_and_valid_preserves_signed_success(self):
        result = self.verify_with_backend({"checked": True, "ok": True})
        self.assertEqual(result["verdict"], "OK")

    def test_a_missing_signature_remains_rejected(self):
        receipt = self.receipt()
        del receipt["signature"]
        result = verifier.verify_receipt(receipt, "synthetic-key")
        self.assertEqual(result["verdict"], "BAD_SIGNATURE")

    def test_expected_key_mismatch_does_not_call_the_backend(self):
        with patch.object(verifier, "_verify_ed25519", side_effect=AssertionError):
            result = verifier.verify_receipt(self.receipt(), "other-published-key")
        self.assertEqual(result["verdict"], "BAD_SIGNATURE")

    def test_field_tampering_takes_precedence_over_unavailable_signature(self):
        receipt = {**self.receipt(), "agent_name": "changed"}
        result = self.verify_with_backend({"checked": False, "ok": None}, receipt)
        self.assertEqual(result["verdict"], "TAMPERED")

    def test_unsigned_commitment_does_not_invoke_a_signature_backend(self):
        receipt = {**self.receipt(), "signed": False}
        with patch.object(verifier, "_verify_ed25519", side_effect=AssertionError):
            result = verifier.verify_receipt(receipt)
        self.assertEqual(result["verdict"], "OK_UNSIGNED")
        self.assertIs(result["signature_checked"], False)


if __name__ == "__main__":
    unittest.main()
