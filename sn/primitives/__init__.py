"""Suite registry."""

from __future__ import annotations

from .base import KEM, KEY_LEN, KeyedHash, PRF, Signature, Suite, SymmetricEnc
from .classical import Ed25519Sig, X25519KEM
from .common import ChaCha20Enc, HmacHash, HmacPRF
from .pq import MLDSA65, MLKEM768

CLASSICAL = Suite(
    id=0x01,
    name="classical",
    kem=X25519KEM(),
    sig=Ed25519Sig(),
    sym=ChaCha20Enc(),
    prf=HmacPRF(),
    hash=HmacHash(),
)

PQ = Suite(
    id=0x02,
    name="pq",
    kem=MLKEM768(),
    sig=MLDSA65(),
    sym=ChaCha20Enc(),
    prf=HmacPRF(),
    hash=HmacHash(),
)

SUITES = {s.name: s for s in (CLASSICAL, PQ)}
SUITES_BY_ID = {s.id: s for s in (CLASSICAL, PQ)}


def get_suite(name: str) -> Suite:
    try:
        return SUITES[name]
    except KeyError:
        raise ValueError(
            f"unknown suite {name!r}; choose from {', '.join(SUITES)}"
        ) from None


__all__ = [
    "CLASSICAL", "PQ", "SUITES", "SUITES_BY_ID", "get_suite", "Suite",
    "KEM", "Signature", "SymmetricEnc", "PRF", "KeyedHash", "KEY_LEN",
]
