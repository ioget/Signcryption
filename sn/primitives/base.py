"""Abstract interfaces for the five building blocks of the SN construction.

Section 3 of the paper (p. 8) lists exactly these: a KEM, a symmetric
encryption scheme, a PRF, a keyed hash function, and a signature scheme.
The construction is generic over all five, so they live behind abstract
interfaces and a suite is just a choice of five concrete implementations.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass

KEY_LEN = 32  # |K| = 2^256; the PRF and keyed hash both range over K


class KEM(abc.ABC):
    """Key encapsulation mechanism; must be IND-CCA secure (Def. 7)."""

    name: str
    pk_len: int
    ct_len: int

    @abc.abstractmethod
    def generate(self) -> tuple[bytes, bytes]:
        """Gen_K -> (sk, pk)."""

    @abc.abstractmethod
    def encap(self, pk: bytes) -> tuple[bytes, bytes]:
        """Ecp -> (shared_secret, c1)."""

    @abc.abstractmethod
    def decap(self, sk: bytes, ct: bytes) -> bytes:
        """Dcp -> shared_secret.  Raises ValueError on malformed input."""

    @abc.abstractmethod
    def public_key(self, sk: bytes) -> bytes:
        """Recover pk from sk; Usc needs pk_rcv to rebuild the hash input."""

    @abc.abstractmethod
    def validate_pk(self, pk: bytes) -> None:
        """Raise ValueError unless pk is a well-formed public key.

        The security proofs omit public key validation for readability
        (p. 10), but the dynamic multi-user model assumes no key
        registration, so this check is exactly where real attacks land.
        """


class Signature(abc.ABC):
    """Signature scheme; sUF-CMA (Def. 8) and resistant to colliding
    signatures (Def. 9)."""

    name: str
    pk_len: int
    sig_len: int

    @abc.abstractmethod
    def generate(self) -> tuple[bytes, bytes]:
        """Gen_S -> (sk, pk)."""

    @abc.abstractmethod
    def public_key(self, sk: bytes) -> bytes:
        """Recover pk from sk; Sc needs pk_sd for the hash on line 18."""

    @abc.abstractmethod
    def sign(self, sk: bytes, msg: bytes) -> bytes: ...

    @abc.abstractmethod
    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        """Must return False rather than raise on an invalid signature."""

    @abc.abstractmethod
    def validate_pk(self, pk: bytes) -> None: ...


class SymmetricEnc(abc.ABC):
    """Symmetric encryption; semantically secure (Def. 1) and resistant to
    key clustering attacks (Def. 2).

    This deployment additionally requires it to be deterministic and
    length preserving, so that a verifier holding the original document can
    recompute c2 instead of carrying it in the QR code.  A stream cipher
    keyed by a value that is fresh for every encapsulation satisfies both.
    """

    name: str

    @abc.abstractmethod
    def encrypt(self, key: bytes, m: bytes) -> bytes: ...

    @abc.abstractmethod
    def decrypt(self, key: bytes, c: bytes) -> bytes: ...


class PRF(abc.ABC):
    """Pseudo-random function over (K, D, R = K)."""

    name: str

    @abc.abstractmethod
    def __call__(self, key: bytes, data: bytes) -> bytes: ...


class KeyedHash(abc.ABC):
    """Keyed hash H : K x M' -> T, collision resistant (Def. 4) and
    resistant to collisions with identical prefix (Def. 5)."""

    name: str

    @abc.abstractmethod
    def __call__(self, key: bytes, data: bytes) -> bytes: ...


@dataclass(frozen=True)
class Suite:
    """One concrete instantiation of the five building blocks."""

    id: int
    name: str
    kem: KEM
    sig: Signature
    sym: SymmetricEnc
    prf: PRF
    hash: KeyedHash

    def fits_in_qr(self) -> bool:
        """Whether one signature's evidence fits a single QR code."""
        return self.evidence_size() <= 2000

    def evidence_size(self) -> int:
        """Approximate evidence payload size in bytes, excluding metadata."""
        return (
            2  # version + suite id
            + KEY_LEN  # tau0
            + self.sig.pk_len
            + self.kem.pk_len
            + self.kem.ct_len
            + self.sig.sig_len
            + KEY_LEN  # MAC tag t
            + 4 * KEY_LEN  # nr
        )
