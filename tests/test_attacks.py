"""Negative tests: each one corresponds to a security property of the paper."""

import os

import pytest

from sn.scheme import (
    Ciphertext,
    _derive,
    _mhat,
    gen_rcv,
    gen_sd,
    n,
    pv,
    sc,
    setup,
    usc,
)


def _flip(data: bytes, index: int = 0) -> bytes:
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


@pytest.mark.parametrize("field", ["t", "sigma", "c1", "c2"])
def test_tampering_any_field_is_rejected(party, field):
    """Strong unforgeability: no component of C may be altered."""
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    C = sc(dp, sk_sd, pk_rcv, b"the original message")
    tampered = Ciphertext(**{**C.__dict__, field: _flip(getattr(C, field))})
    assert usc(dp, sk_rcv, pk_sd, tampered) is None


def test_wrong_sender_key_is_rejected(party):
    """m-hat binds pk_sd, so a different claimed signer cannot verify."""
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    C = sc(dp, sk_sd, pk_rcv, b"hello")
    _, other_pk_sd = gen_sd(dp)
    assert usc(dp, sk_rcv, other_pk_sd, C) is None


def test_wrong_receiver_key_is_rejected(party):
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    C = sc(dp, sk_sd, pk_rcv, b"hello")
    other_sk_rcv, _ = gen_rcv(dp)
    assert usc(dp, other_sk_rcv, pk_sd, C) is None


def test_evidence_from_one_message_does_not_verify_another(party):
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    C1 = sc(dp, sk_sd, pk_rcv, b"message one")
    C2 = sc(dp, sk_sd, pk_rcv, b"message two")
    nr1 = n(dp, sk_rcv, pk_sd, C1)
    assert pv(dp, C2, b"message two", nr1, pk_sd, pk_rcv) is False


def test_resigning_attack_is_blocked_by_the_mac_tag():
    """The attack that line 19 of the scheme exists to prevent.

    An insider attacker holds sk_sd and wants a C' != C that still
    unsigncrypts to m, so it can submit C' to a decryption oracle and win
    the confidentiality game.  Here the attacker is given even more than
    reality allows -- m-hat itself, which really needs sk_rcv -- and it
    still fails, because swapping sigma invalidates t = Prf(tau1', sigma)
    and tau1' is reachable only through the receiver's private key.

    Uses the PQ suite because ML-DSA is randomized, so re-signing the same
    m-hat genuinely yields a different, valid signature.
    """
    dp = setup("pq")
    sk_sd, pk_sd = gen_sd(dp)
    sk_rcv, pk_rcv = gen_rcv(dp)
    m = b"transfer 100 to alice"
    C = sc(dp, sk_sd, pk_rcv, m)

    # Test-only oracle standing in for knowledge the attacker cannot have.
    keys = _derive(dp.suite.kem.decap(sk_rcv, C.c1))
    mhat = _mhat(dp, pk_sd, keys, dp.suite.prf(keys.t2, m), C.c1, C.c2, pk_rcv)

    sigma2 = dp.suite.sig.sign(sk_sd, mhat)
    assert sigma2 != C.sigma, "ML-DSA should be randomized"
    assert dp.suite.sig.verify(pk_sd, mhat, sigma2), "the new signature is valid"

    forged = Ciphertext(t=C.t, sigma=sigma2, c1=C.c1, c2=C.c2)
    assert usc(dp, sk_rcv, pk_sd, forged) is None, "the MAC tag must stop this"

    # And to show the tag is precisely what stopped it: recompute t with
    # tau1' -- which the attacker has no way to obtain -- and the same
    # forgery sails through.
    repaired = Ciphertext(
        t=dp.suite.prf(keys.t1p, sigma2), sigma=sigma2, c1=C.c1, c2=C.c2
    )
    assert usc(dp, sk_rcv, pk_sd, repaired) == m


def test_malformed_public_keys_are_rejected(party):
    """The proofs omit public key validation (p. 10); the code must not."""
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    with pytest.raises(ValueError):
        sc(dp, sk_sd, pk_rcv[:-1], b"x")
    C = sc(dp, sk_sd, pk_rcv, b"x")
    nr = n(dp, sk_rcv, pk_sd, C)
    assert pv(dp, C, b"x", nr, pk_sd[:-1], pk_rcv) is False
    assert pv(dp, C, b"x", nr, pk_sd, pk_rcv[:-1]) is False


def test_malformed_encapsulation_is_rejected(party):
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    C = sc(dp, sk_sd, pk_rcv, b"x")
    assert usc(dp, sk_rcv, pk_sd, Ciphertext(C.t, C.sigma, b"short", C.c2)) is None


def test_truncated_document_is_rejected(party):
    """Length is covered because tau3 = Prf(tau2, m) takes the whole m."""
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    m = os.urandom(500)
    C = sc(dp, sk_sd, pk_rcv, m)
    nr = n(dp, sk_rcv, pk_sd, C)
    assert pv(dp, C, m[:499], nr, pk_sd, pk_rcv) is False
