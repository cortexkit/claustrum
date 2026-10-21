#!/usr/bin/env python3
"""Open a vault-sealed `credential.seal` reply with an HPKE receiver that is not the
Rust `hpke` crate the vault seals with.

WHY. A seal checked only by the same library that made it proves the library agrees
with itself. The phone that opens these pushes runs a different HPKE implementation,
so the property worth checking is that a separate, from-the-RFC receiver opens what
the vault produced. This file is that receiver: RFC 9180 Auth mode (mode 2) for
DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305, written from the RFC's
pseudocode on top of the `cryptography` package's raw X25519, HMAC-SHA256 and
ChaCha20-Poly1305 primitives. No HPKE library is involved.

WHAT IT CHECKS, in order, and it exits non-zero on the first failure:
  1. The receiver itself is right: it opens every published encryption of the RFC 9180
     mode-2 vector for this suite (crates/credentials-core/tests/fixtures/
     rfc9180-a2-auth.json) and derives the published shared secret, key and nonce.
  2. The vault's output opens: the `credential.seal` success reply pinned in
     crates/credentials-module/tests/fixtures/enrollment_wire_contract.json was produced
     by the daemon's real request dispatcher (`key_and_scoped_wire_fixture_pins_real_
     success_replies`) from synthetic scalars: vault key bytes 32..63, recipient key
     bytes 64..95. It must open to the request's plaintext under the vault key's
     public half, and the reply's key_id must name that public half.
  3. Tamper controls: flipping one bit of the ciphertext, of the encapsulated key, or
     of the sender public key must each make the open fail.

Usage:
  python3 scripts/hpke-independent-open.py

Needs the `cryptography` package (any release with X25519 and ChaCha20Poly1305).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTOR = ROOT / "crates/credentials-core/tests/fixtures/rfc9180-a2-auth.json"
WIRE_FIXTURE = ROOT / "crates/credentials-module/tests/fixtures/enrollment_wire_contract.json"

KEM_ID, KDF_ID, AEAD_ID = 0x0020, 0x0001, 0x0003
MODE_AUTH = 0x02
N_SECRET, N_K, N_N = 32, 32, 12


def _primitives():
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError as error:  # pragma: no cover - environment dependent
        raise SystemExit(f"REFUSING: the `cryptography` package is required ({error})")
    return InvalidTag, X25519PrivateKey, X25519PublicKey, ChaCha20Poly1305, Encoding, PublicFormat


(InvalidTag, X25519PrivateKey, X25519PublicKey, ChaCha20Poly1305, Encoding, PublicFormat) = _primitives()


# RFC 9180 section 4: labeled HKDF. The KEM uses suite_id "KEM" || I2OSP(kem_id, 2);
# the key schedule uses "HPKE" || kem_id || kdf_id || aead_id.
KEM_SUITE = b"KEM" + KEM_ID.to_bytes(2, "big")
HPKE_SUITE = b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big") + AEAD_ID.to_bytes(2, "big")


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def labeled_extract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return hkdf_extract(salt, b"HPKE-v1" + suite + label + ikm)


def labeled_expand(suite: bytes, prk: bytes, label: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite + label + info, length)


def public_of(secret: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(secret)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def dh(secret: bytes, public: bytes) -> bytes:
    shared = X25519PrivateKey.from_private_bytes(secret).exchange(X25519PublicKey.from_public_bytes(public))
    # RFC 9180 section 7.1.4: an all-zero output must be refused. (`cryptography`
    # already raises on it; the explicit check keeps this receiver honest on its own.)
    if shared == b"\x00" * 32:
        raise ValueError("all-zero X25519 output")
    return shared


def auth_decap(enc: bytes, recipient_secret: bytes, sender_public: bytes) -> bytes:
    """RFC 9180 section 4.1 AuthDecap(enc, skR, pkS)."""
    dh_value = dh(recipient_secret, enc) + dh(recipient_secret, sender_public)
    kem_context = enc + public_of(recipient_secret) + sender_public
    eae_prk = labeled_extract(KEM_SUITE, b"", b"eae_prk", dh_value)
    return labeled_expand(KEM_SUITE, eae_prk, b"shared_secret", kem_context, N_SECRET)


def key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    """RFC 9180 section 5.1 KeySchedule for mode_auth (no PSK)."""
    psk_id_hash = labeled_extract(HPKE_SUITE, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(HPKE_SUITE, b"", b"info_hash", info)
    context = bytes([MODE_AUTH]) + psk_id_hash + info_hash
    secret = labeled_extract(HPKE_SUITE, shared_secret, b"secret", b"")
    key = labeled_expand(HPKE_SUITE, secret, b"key", context, N_K)
    base_nonce = labeled_expand(HPKE_SUITE, secret, b"base_nonce", context, N_N)
    return key, base_nonce


def open_auth(
    recipient_secret: bytes,
    sender_public: bytes,
    enc: bytes,
    ciphertext: bytes,
    info: bytes,
    aad: bytes,
    seq: int = 0,
) -> bytes:
    key, base_nonce = key_schedule(auth_decap(enc, recipient_secret, sender_public), info)
    nonce = bytes(a ^ b for a, b in zip(base_nonce, seq.to_bytes(N_N, "big")))
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


def check_vector() -> int:
    v = json.loads(VECTOR.read_text(encoding="utf-8"))
    if (v["mode"], v["kem_id"], v["kdf_id"], v["aead_id"]) != (MODE_AUTH, KEM_ID, KDF_ID, AEAD_ID):
        raise SystemExit("REFUSING: the vendored vector is not mode 2 of this suite")
    h = bytes.fromhex
    shared = auth_decap(h(v["enc"]), h(v["skRm"]), h(v["pkSm"]))
    if shared != h(v["shared_secret"]):
        raise SystemExit("REFUSING: AuthDecap does not reproduce the published shared_secret")
    key, nonce = key_schedule(shared, h(v["info"]))
    if (key, nonce) != (h(v["key"]), h(v["base_nonce"])):
        raise SystemExit("REFUSING: the key schedule does not reproduce the published key/nonce")
    for seq, encryption in enumerate(v["encryptions"]):
        opened = open_auth(
            h(v["skRm"]), h(v["pkSm"]), h(v["enc"]), h(encryption["ct"]), h(v["info"]), h(encryption["aad"]), seq
        )
        if opened != h(encryption["pt"]):
            raise SystemExit(f"REFUSING: published sequence {seq} opened to the wrong plaintext")
    return len(v["encryptions"])


def seal_sample() -> dict:
    fixture = json.loads(WIRE_FIXTURE.read_text(encoding="utf-8"))
    rows = [row for row in fixture["operations"] if row["op"] == "credential.seal"]
    if len(rows) != 1:
        raise SystemExit(f"REFUSING: expected one credential.seal row in the wire fixture, found {len(rows)}")
    request = json.loads(rows[0]["request"])
    reply = json.loads(rows[0]["success"][0])["result"]
    b64 = base64.b64decode
    sender_secret = bytes(range(32, 64))
    recipient_secret = bytes(range(64, 96))
    if b64(request["recipient_public_key_b64"]) != public_of(recipient_secret):
        raise SystemExit("REFUSING: the fixture's recipient is not the synthetic recipient key")
    return {
        "recipient_secret": recipient_secret,
        "sender_public": public_of(sender_secret),
        "enc": b64(reply["enc_b64"]),
        "ciphertext": b64(reply["ciphertext_b64"]),
        "info": b64(request["info_b64"]),
        "aad": b64(request["aad_b64"]),
        "plaintext": b64(request["plaintext_b64"]),
        "key_id": reply["key_id"],
    }


def flip(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


def main() -> int:
    published = check_vector()
    print(f"independent receiver: opened all {published} published RFC 9180 mode-2 encryptions")

    s = seal_sample()
    opened = open_auth(s["recipient_secret"], s["sender_public"], s["enc"], s["ciphertext"], s["info"], s["aad"])
    if opened != s["plaintext"]:
        raise SystemExit("REFUSING: the vault's seal opened to a different plaintext")
    if s["key_id"] != hashlib.sha256(s["sender_public"]).hexdigest()[:16]:
        raise SystemExit("REFUSING: the reply's key_id does not name the vault key's public half")
    print(f"vault seal: opened {len(opened)} bytes under the vault key (key_id {s['key_id']})")

    for name, tampered in [
        ("ciphertext", dict(s, ciphertext=flip(s["ciphertext"]))),
        ("enc", dict(s, enc=flip(s["enc"]))),
        ("sender public key", dict(s, sender_public=flip(s["sender_public"]))),
    ]:
        try:
            open_auth(
                tampered["recipient_secret"],
                tampered["sender_public"],
                tampered["enc"],
                tampered["ciphertext"],
                tampered["info"],
                tampered["aad"],
            )
        except (InvalidTag, ValueError):
            print(f"tamper control: one flipped bit in the {name} fails to open")
            continue
        raise SystemExit(f"REFUSING: a one-bit change to the {name} still opened")
    return 0


if __name__ == "__main__":
    sys.exit(main())
