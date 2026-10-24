"""The SN signcryption scheme.

Togde & Sarr, "An Efficient Generic Insider Secure Signcryption with
Non-Interactive Non-Repudiation", Section 3, p. 9.  The seven algorithms
below follow the pseudocode lines 10-35 of that page directly; line
numbers are cited in the docstrings so the code can be read beside it.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from .codec import pack, unpack
from .primitives import KEY_LEN, Suite, get_suite

_KEY_INFO = b"SN/v1/keys"


@dataclass(frozen=True)
class DomainParams:
    """dp = (dp_K, dp_S, E, Prf, H, tau0), line 11.

    dp_K and dp_S are carried implicitly by the suite.  tau0 is the public
    hash key; it is drawn once by Setup and must stay fixed thereafter.
    """

    suite: Suite
    tau0: bytes

    def __post_init__(self) -> None:
        if len(self.tau0) != KEY_LEN:
            raise ValueError("tau0 must be 32 bytes")


@dataclass(frozen=True)
class Keys:
    """The four keys K' = K^4 produced by one encapsulation.

    As non-repudiation evidence this is exactly the nr of algorithm N.
    """

    t1: bytes   # symmetric encryption key for the payload
    t1p: bytes  # PRF key for the MAC tag over the signature
    t2: bytes   # PRF key producing tau3, binding the signature to m
    t2p: bytes  # extra secret hashed into m-hat

    def to_bytes(self) -> bytes:
        return self.t1 + self.t1p + self.t2 + self.t2p

    @classmethod
    def from_bytes(cls, b: bytes) -> "Keys":
        if len(b) != 4 * KEY_LEN:
            raise ValueError("nr must be 128 bytes")
        k = KEY_LEN
        return cls(b[:k], b[k : 2 * k], b[2 * k : 3 * k], b[3 * k :])


@dataclass(frozen=True)
class Ciphertext:
    """C = (t, sigma, c1, c2), line 19."""

    t: bytes
    sigma: bytes
    c1: bytes
    c2: bytes

    def to_bytes(self) -> bytes:
        return pack(self.t, self.sigma, self.c1, self.c2)

    @classmethod
    def from_bytes(cls, b: bytes) -> "Ciphertext":
        return cls(*unpack(b, count=4))


# --- the scheme -------------------------------------------------------------


def setup(suite: str = "classical", tau0: bytes | None = None) -> DomainParams:
    """Setup(k), lines 10-11."""
    return DomainParams(suite=get_suite(suite), tau0=tau0 or os.urandom(KEY_LEN))


def gen_sd(dp: DomainParams) -> tuple[bytes, bytes]:
    """Gen_sd(dp), lines 12-13 -> the sender's signing key pair."""
    return dp.suite.sig.generate()


def gen_rcv(dp: DomainParams) -> tuple[bytes, bytes]:
    """Gen_rcv(dp), lines 14-15 -> the receiver's KEM key pair."""
    return dp.suite.kem.generate()


def _derive(shared: bytes) -> Keys:
    """Split one encapsulated secret into K' = K^4.

    The paper requires K' = K^4 and notes this "can be achieved by using,
    if needed, an appropriate key derivation function" (p. 8).
    """
    okm = HKDFExpand(
        algorithm=hashes.SHA256(), length=4 * KEY_LEN, info=_KEY_INFO
    ).derive(shared)
    return Keys.from_bytes(okm)


def _mhat(
    dp: DomainParams,
    pk_sd: bytes,
    keys: Keys,
    tau3: bytes,
    c1: bytes,
    c2: bytes,
    pk_rcv: bytes,
) -> bytes:
    """m-hat = H(tau0, (pk_sd, tau2, tau2', tau3, c1, c2, pk_rcv)), line 18.

    Every field is length-prefixed by pack(): c1 and c2 are adjacent and
    variable length, so without that an attacker could move bytes across
    the boundary and collide the hash for free.
    """
    return dp.suite.hash(
        dp.tau0, pack(pk_sd, keys.t2, keys.t2p, tau3, c1, c2, pk_rcv)
    )


def sc(dp: DomainParams, sk_sd: bytes, pk_rcv: bytes, m: bytes) -> Ciphertext:
    """Sc(sk_sd, pk_rcv, m), lines 16-19."""
    s = dp.suite
    s.kem.validate_pk(pk_rcv)
    pk_sd = s.sig.public_key(sk_sd)

    shared, c1 = s.kem.encap(pk_rcv)
    keys = _derive(shared)
    c2 = s.sym.encrypt(keys.t1, m)
    tau3 = s.prf(keys.t2, m)

    mhat = _mhat(dp, pk_sd, keys, tau3, c1, c2, pk_rcv)
    sigma = s.sig.sign(sk_sd, mhat)
    t = s.prf(keys.t1p, sigma)
    return Ciphertext(t=t, sigma=sigma, c1=c1, c2=c2)


def _open(
    dp: DomainParams, sk_rcv: bytes, pk_sd: bytes, C: Ciphertext
) -> tuple[bytes, Keys] | None:
    """Shared body of Usc (lines 20-24) and N (lines 25-29).

    Both algorithms run identical checks and differ only in what they
    return, so the checking is written once.
    """
    s = dp.suite
    s.sig.validate_pk(pk_sd)
    try:
        shared = s.kem.decap(sk_rcv, C.c1)
    except ValueError:
        return None
    keys = _derive(shared)
    pk_rcv = s.kem.public_key(sk_rcv)

    m = s.sym.decrypt(keys.t1, C.c2)
    tau3 = s.prf(keys.t2, m)
    mhat = _mhat(dp, pk_sd, keys, tau3, C.c1, C.c2, pk_rcv)

    # Both checks are evaluated before branching, and the tag comparison is
    # constant time.
    d = s.sig.verify(pk_sd, mhat, C.sigma)
    tag_ok = hmac.compare_digest(C.t, s.prf(keys.t1p, C.sigma))
    if d and tag_ok:
        return m, keys
    return None


def usc(
    dp: DomainParams, sk_rcv: bytes, pk_sd: bytes, C: Ciphertext
) -> bytes | None:
    """Usc(sk_rcv, pk_sd, C), lines 20-24.  Returns m, or None for the
    error symbol.  Deterministic, as Def. 10(e) requires."""
    out = _open(dp, sk_rcv, pk_sd, C)
    return None if out is None else out[0]


def n(
    dp: DomainParams, sk_rcv: bytes, pk_sd: bytes, C: Ciphertext
) -> Keys | None:
    """N(sk_rcv, pk_sd, C), lines 25-29 -> the non-repudiation evidence
    nr = (tau1, tau1', tau2, tau2'), or None.

    Note that nr contains tau1, so whoever holds it can decrypt c2.
    Releasing evidence settles a dispute at the cost of that message's
    confidentiality.
    """
    out = _open(dp, sk_rcv, pk_sd, C)
    return None if out is None else out[1]


def pv_checks(
    dp: DomainParams,
    C: Ciphertext,
    m: bytes,
    nr: Keys,
    pk_sd: bytes,
    pk_rcv: bytes,
) -> dict[str, bool]:
    """The individual checks PV performs, for reporting.

    PV itself is just the conjunction of these; keeping them separate lets
    the CLI say which check failed without duplicating the logic.
    """
    s = dp.suite
    try:
        s.sig.validate_pk(pk_sd)
        s.kem.validate_pk(pk_rcv)
    except ValueError:
        return {"public_keys": False, "plaintext": False, "signature": False, "mac_tag": False}

    checks = {"public_keys": True}
    checks["plaintext"] = hmac.compare_digest(s.sym.decrypt(nr.t1, C.c2), m)  # line 32

    tau3 = s.prf(nr.t2, m)
    mhat = _mhat(dp, pk_sd, nr, tau3, C.c1, C.c2, pk_rcv)
    checks["signature"] = s.sig.verify(pk_sd, mhat, C.sigma)
    checks["mac_tag"] = hmac.compare_digest(C.t, s.prf(nr.t1p, C.sigma))
    return checks


def pv(
    dp: DomainParams,
    C: Ciphertext,
    m: bytes,
    nr: Keys,
    pk_sd: bytes,
    pk_rcv: bytes,
) -> bool:
    """PV(C, m, nr, pk_sd, pk_rcv), lines 30-35.

    Public: needs no private key and no interaction with either party.
    This is the non-interactive non-repudiation property.
    """
    return all(pv_checks(dp, C, m, nr, pk_sd, pk_rcv).values())
