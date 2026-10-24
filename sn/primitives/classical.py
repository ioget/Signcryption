"""Classical suite: X25519 DHKEM + Ed25519.

Ed25519 rather than ECDSA: ECDSA is malleable (s -> n-s), so it is not
sUF-CMA and would break Theorem 2 outright.  Ed25519 with canonical checks
was shown SUF-CMA by Brendel et al., and because it hashes the message
before signing, colliding signatures (Def. 9) reduce to a SHA-512
collision -- exactly the argument the paper makes on p. 18.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .base import KEY_LEN, KEM, Signature

_DHKEM_LABEL = b"SN/v1/dhkem-x25519"


class X25519KEM(KEM):
    """DHKEM(X25519, HKDF-SHA256), in the style of RFC 9180.

    Note for the write-up: DHKEM is IND-CCA in the random oracle model, so
    instantiating with it keeps the SN *construction* standard-model while
    the KEM itself is not.  A genuinely end-to-end standard-model instance
    would need something like Cramer-Shoup here -- which is precisely what
    the pluggable KEM interface is for.
    """

    name = "x25519-dhkem"
    pk_len = 32
    ct_len = 32

    def generate(self) -> tuple[bytes, bytes]:
        sk = x25519.X25519PrivateKey.generate()
        return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()

    def _kdf(self, dh: bytes, pk_e: bytes, pk_r: bytes) -> bytes:
        # Both public keys are bound into the KDF; without that binding the
        # encapsulation is not CCA secure.
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_LEN,
            salt=b"",
            info=_DHKEM_LABEL + pk_e + pk_r,
        ).derive(dh)

    def encap(self, pk: bytes) -> tuple[bytes, bytes]:
        self.validate_pk(pk)
        pk_r = x25519.X25519PublicKey.from_public_bytes(pk)
        sk_e = x25519.X25519PrivateKey.generate()
        pk_e = sk_e.public_key().public_bytes_raw()
        dh = sk_e.exchange(pk_r)  # raises on a small-order peer key
        return self._kdf(dh, pk_e, pk), pk_e

    def decap(self, sk: bytes, ct: bytes) -> bytes:
        if len(ct) != self.ct_len:
            raise ValueError("bad encapsulation length")
        sk_r = x25519.X25519PrivateKey.from_private_bytes(sk)
        pk_r = sk_r.public_key().public_bytes_raw()
        dh = sk_r.exchange(x25519.X25519PublicKey.from_public_bytes(ct))
        return self._kdf(dh, ct, pk_r)

    def public_key(self, sk: bytes) -> bytes:
        return (
            x25519.X25519PrivateKey.from_private_bytes(sk)
            .public_key()
            .public_bytes_raw()
        )

    def validate_pk(self, pk: bytes) -> None:
        if len(pk) != self.pk_len:
            raise ValueError(f"X25519 public key must be {self.pk_len} bytes")
        x25519.X25519PublicKey.from_public_bytes(pk)


class Ed25519Sig(Signature):
    name = "ed25519"
    pk_len = 32
    sig_len = 64

    def generate(self) -> tuple[bytes, bytes]:
        sk = ed25519.Ed25519PrivateKey.generate()
        return sk.private_bytes_raw(), sk.public_key().public_bytes_raw()

    def public_key(self, sk: bytes) -> bytes:
        return (
            ed25519.Ed25519PrivateKey.from_private_bytes(sk)
            .public_key()
            .public_bytes_raw()
        )

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return ed25519.Ed25519PrivateKey.from_private_bytes(sk).sign(msg)

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
            return True
        except (InvalidSignature, ValueError):
            return False

    def validate_pk(self, pk: bytes) -> None:
        if len(pk) != self.pk_len:
            raise ValueError(f"Ed25519 public key must be {self.pk_len} bytes")
        ed25519.Ed25519PublicKey.from_public_bytes(pk)
