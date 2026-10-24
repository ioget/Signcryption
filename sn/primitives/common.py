"""Primitives shared by every suite: ChaCha20, HMAC-SHA256 as PRF and as H."""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from .base import KEY_LEN, KeyedHash, PRF, SymmetricEnc


class ChaCha20Enc(SymmetricEnc):
    """ChaCha20 keystream with an all-zero nonce.

    Reusing a fixed nonce is safe here, and only here, because the key is
    tau1, which comes fresh out of a KEM encapsulation for every single
    message: no two encryptions ever share a key.  Being deterministic and
    length preserving is what lets the verifier rebuild c2 from the
    original document rather than carry it in the QR code.

    Deliberately not an AEAD.  Integrity comes from sigma and the tag t;
    an AEAD here would add a second, redundant authenticator.
    """

    name = "chacha20"
    _NONCE = b"\x00" * 16

    def _xor(self, key: bytes, data: bytes) -> bytes:
        if len(key) != KEY_LEN:
            raise ValueError("ChaCha20 requires a 32-byte key")
        enc = Cipher(algorithms.ChaCha20(key, self._NONCE), mode=None).encryptor()
        return enc.update(data) + enc.finalize()

    encrypt = _xor

    def decrypt(self, key: bytes, c: bytes) -> bytes:
        return self._xor(key, c)


class HmacPRF(PRF):
    """HMAC-SHA256.  Domain is arbitrary-length (tau3 = Prf(tau2, m) takes
    the whole message), range is K = {0,1}^256."""

    name = "hmac-sha256"

    def __call__(self, key: bytes, data: bytes) -> bytes:
        if len(key) != KEY_LEN:
            raise ValueError("PRF requires a 32-byte key")
        return hmac.new(key, data, hashlib.sha256).digest()


class HmacHash(KeyedHash):
    """HMAC-SHA256 used as the keyed hash H : K x M' -> T.

    tau0 is the public hash key drawn once by Setup; keying H is what lets
    collision resistance be stated as a concrete assumption (Def. 4) rather
    than an asymptotic one.
    """

    name = "hmac-sha256"

    def __call__(self, key: bytes, data: bytes) -> bytes:
        if len(key) != KEY_LEN:
            raise ValueError("H requires a 32-byte key")
        return hmac.new(key, data, hashlib.sha256).digest()
