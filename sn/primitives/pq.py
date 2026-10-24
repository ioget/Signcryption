"""Post-quantum suite: ML-KEM-768 + ML-DSA-65 (FIPS 203 / 204).

The paper closes by noting SN "can be instantiated with adequate present
and future (including quantum-resistant) primitives" (p. 18).  This suite
is that claim, executed.  Its evidence payload is ~7.8 KB, well over the
2953-byte QR ceiling, so the CLI falls back to a sidecar file for it.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem

from .base import KEM, Signature


class MLKEM768(KEM):
    name = "ml-kem-768"
    pk_len = 1184
    ct_len = 1088
    _seed_len = 64

    def generate(self) -> tuple[bytes, bytes]:
        sk = mlkem.MLKEM768PrivateKey.generate()
        return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()

    def encap(self, pk: bytes) -> tuple[bytes, bytes]:
        self.validate_pk(pk)
        # encapsulate() yields (shared_secret, ciphertext), in that order.
        return mlkem.MLKEM768PublicKey.from_public_bytes(pk).encapsulate()

    def decap(self, sk: bytes, ct: bytes) -> bytes:
        if len(ct) != self.ct_len:
            raise ValueError("bad encapsulation length")
        return mlkem.MLKEM768PrivateKey.from_seed_bytes(sk).decapsulate(ct)

    def public_key(self, sk: bytes) -> bytes:
        return (
            mlkem.MLKEM768PrivateKey.from_seed_bytes(sk)
            .public_key()
            .public_bytes_raw()
        )

    def validate_pk(self, pk: bytes) -> None:
        if len(pk) != self.pk_len:
            raise ValueError(f"ML-KEM-768 public key must be {self.pk_len} bytes")
        mlkem.MLKEM768PublicKey.from_public_bytes(pk)


class MLDSA65(Signature):
    name = "ml-dsa-65"
    pk_len = 1952
    sig_len = 3309

    def generate(self) -> tuple[bytes, bytes]:
        sk = mldsa.MLDSA65PrivateKey.generate()
        return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()

    def public_key(self, sk: bytes) -> bytes:
        return (
            mldsa.MLDSA65PrivateKey.from_seed_bytes(sk)
            .public_key()
            .public_bytes_raw()
        )

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return mldsa.MLDSA65PrivateKey.from_seed_bytes(sk).sign(msg)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            mldsa.MLDSA65PublicKey.from_public_bytes(pk).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False

    def validate_pk(self, pk: bytes) -> None:
        if len(pk) != self.pk_len:
            raise ValueError(f"ML-DSA-65 public key must be {self.pk_len} bytes")
        mldsa.MLDSA65PublicKey.from_public_bytes(pk)
