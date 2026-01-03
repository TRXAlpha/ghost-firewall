import hmac
import os
import hashlib


def build_challenge(secret: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(16)
    digest = hmac.new(secret, nonce, hashlib.sha256).digest()
    return nonce, digest


def verify_challenge(secret: bytes, nonce: bytes, digest: bytes) -> bool:
    expected = hmac.new(secret, nonce, hashlib.sha256).digest()
    return hmac.compare_digest(expected, digest)
