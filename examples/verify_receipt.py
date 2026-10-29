#!/usr/bin/env python3
"""Offline BuddyLists souvenir-receipt verifier. Stdlib + optional cryptography.

Never phones the issuer for the hash check. Ed25519 is verified locally when
signed:true and the cryptography package (or openssl) is available.

jcs_sha256 is an unsigned interop digest — not a second signature.
A valid hash with signed:false is a hash commitment, not an identity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

SIGNED_FIELDS = [
    "receipt_type",
    "issued_by",
    "issued_at",
    "agent_name",
    "owner_email_sha256",
    "note",
    "epoch",
]


def compact(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def rebuild_canonical(receipt: dict) -> str:
    built = {key: receipt[key] if key in receipt else None for key in SIGNED_FIELDS}
    return compact(built)


def rebuild_jcs(receipt: dict) -> str:
    built = {key: receipt[key] if key in receipt else None for key in SIGNED_FIELDS}
    ordered = {key: built[key] for key in sorted(built)}
    return compact(ordered)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _verify_ed25519(message: bytes, signature_b64: str, public_key_b64: str) -> dict:
    import base64

    try:
        sig = base64.b64decode(signature_b64)
        raw = base64.b64decode(public_key_b64)
    except Exception as exc:  # noqa: BLE001
        return {"checked": True, "ok": False, "reason": f"base64: {exc}"}
    if len(raw) != 32:
        return {"checked": True, "ok": False, "reason": f"public key length {len(raw)}, expected 32"}
    if len(sig) != 64:
        return {"checked": True, "ok": False, "reason": f"signature length {len(sig)}, expected 64"}

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(raw).verify(sig, message)
        return {"checked": True, "ok": True, "reason": "valid"}
    except ImportError:
        pass
    except Exception as exc:  # noqa: BLE001
        return {"checked": True, "ok": False, "reason": str(exc)}

    try:
        import subprocess
        import tempfile
        from pathlib import Path

        der_prefix = bytes.fromhex("302a300506032b6570032100")
        with tempfile.TemporaryDirectory() as tmp:
            pub = Path(tmp) / "pub.der"
            sigf = Path(tmp) / "sig.bin"
            msgf = Path(tmp) / "msg.bin"
            pub.write_bytes(der_prefix + raw)
            sigf.write_bytes(sig)
            msgf.write_bytes(message)
            proc = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(pub),
                    "-keyform",
                    "DER",
                    "-sigfile",
                    str(sigf),
                    "-rawin",
                    "-in",
                    str(msgf),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            ok = proc.returncode == 0
            reason = "valid" if ok else (proc.stderr or proc.stdout or "openssl reject").strip()
            return {"checked": True, "ok": ok, "reason": reason}
    except FileNotFoundError:
        return {
            "checked": False,
            "ok": None,
            "reason": "no cryptography package and no openssl — hash checked only",
        }


def coerce_receipt(payload: dict) -> dict:
    if "payload_sha256" in payload and "canonical" in payload:
        return payload
    inner = payload.get("receipt")
    if isinstance(inner, dict) and "payload_sha256" in inner:
        return inner
    raise ValueError("not a souvenir receipt (missing payload_sha256 / canonical)")


def verify_receipt(receipt: dict, expected_public_key_b64: str | None = None) -> dict[str, Any]:
    receipt = coerce_receipt(receipt)
    rebuilt = rebuild_canonical(receipt)
    provided = receipt.get("canonical")
    fields_match = None if not isinstance(provided, str) else rebuilt == provided
    payload_source = provided if isinstance(provided, str) else rebuilt
    payload = sha256_hex(payload_source)
    hash_ok = receipt.get("payload_sha256") == payload

    rebuilt_jcs = rebuild_jcs(receipt)
    jcs_hash = sha256_hex(rebuilt_jcs)
    jcs_ok = None if "jcs_sha256" not in receipt else receipt.get("jcs_sha256") == jcs_hash

    signed = receipt.get("signed") is True
    signature: dict[str, Any] = {"checked": False, "ok": None, "reason": "not signed"}
    if signed:
        key = receipt.get("public_key_b64") or expected_public_key_b64
        if (
            expected_public_key_b64
            and receipt.get("public_key_b64")
            and expected_public_key_b64 != receipt.get("public_key_b64")
        ):
            signature = {
                "checked": True,
                "ok": False,
                "reason": "embedded public key does not match published key",
            }
        elif key and receipt.get("signature"):
            signature = _verify_ed25519(payload_source.encode("utf-8"), receipt["signature"], key)
        else:
            signature = {"checked": True, "ok": False, "reason": "signed:true but missing signature or key"}

    if not hash_ok or fields_match is False:
        verdict = "TAMPERED"
    elif signed and (
        signature.get("checked") is not True or signature.get("ok") is not True
    ):
        verdict = "BAD_SIGNATURE"
    elif not signed:
        verdict = "OK_UNSIGNED"
    else:
        verdict = "OK"

    return {
        "verdict": verdict,
        "fields_match": fields_match,
        "hash_ok": hash_ok,
        "signature_ok": signature.get("ok"),
        "signature_checked": signature.get("checked"),
        "signature_reason": signature.get("reason"),
        "signed": signed,
        "signing_status": receipt.get("signing_status") or ("LIVE" if signed else "DARK"),
        "jcs_ok": jcs_ok,
        "jcs_note": "unsigned interop digest — not a second signature",
        "rebuilt_canonical": rebuilt,
        "rebuilt_payload_sha256": payload,
        "what_it_is_not": "Not identity, reputation, or authorization. Content commitment only.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline BuddyLists receipt verifier")
    parser.add_argument("file", nargs="?", help="receipt JSON file (stdin if omitted)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    raw = sys.stdin.read() if not args.file else open(args.file, encoding="utf-8").read()
    receipt = json.loads(raw)
    result = verify_receipt(receipt)
    if args.json:
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"verdict     {result['verdict']}")
        print(f"fields      {result['fields_match']}")
        print(f"hash        {result['hash_ok']}")
        print(f"signature   {result['signature_ok']} ({result['signature_reason']})")
        print(f"signed      {result['signed']}  {result['signing_status']}")
        print(result["what_it_is_not"])
    return 1 if result["verdict"] in {"TAMPERED", "BAD_SIGNATURE"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
