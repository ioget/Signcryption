"""Correctness of the seven algorithms (paper p. 9)."""

import os

from sn.scheme import Ciphertext, n, pv, sc, setup, usc


def test_consistency(party):
    """Usc(sk_rcv, pk_sd, Sc(sk_sd, pk_rcv, m)) == m, for all m."""
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    for size in (0, 1, 55, 4096):
        m = os.urandom(size)
        assert usc(dp, sk_rcv, pk_sd, sc(dp, sk_sd, pk_rcv, m)) == m


def test_ninr_evidence_verifies(party):
    """If nr <- N(...) then 1 = PV(C, m, nr, pk_sd, pk_rcv)."""
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    m = b"the quick brown fox"
    C = sc(dp, sk_sd, pk_rcv, m)
    nr = n(dp, sk_rcv, pk_sd, C)
    assert nr is not None
    assert pv(dp, C, m, nr, pk_sd, pk_rcv) is True


def test_pv_rejects_a_different_message(party):
    """Soundness of non-repudiation: PV must not accept m' != m."""
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    m = b"pay 100 euros"
    C = sc(dp, sk_sd, pk_rcv, m)
    nr = n(dp, sk_rcv, pk_sd, C)
    assert pv(dp, C, b"pay 900 euros", nr, pk_sd, pk_rcv) is False


def test_usc_is_deterministic(party):
    """Required by Def. 10(e), and by PV consistency."""
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    C = sc(dp, sk_sd, pk_rcv, b"abc")
    assert usc(dp, sk_rcv, pk_sd, C) == usc(dp, sk_rcv, pk_sd, C) == b"abc"


def test_ciphertext_serialisation(party):
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    C = sc(dp, sk_sd, pk_rcv, os.urandom(300))
    assert Ciphertext.from_bytes(C.to_bytes()) == C


def test_each_signcryption_is_fresh(party):
    """A fresh encapsulation per message is what makes the fixed ChaCha20
    nonce safe."""
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    m = b"same message"
    a, b = sc(dp, sk_sd, pk_rcv, m), sc(dp, sk_sd, pk_rcv, m)
    assert a.c1 != b.c1 and a.c2 != b.c2


def test_suite_sizes():
    """Guards the QR capacity decision."""
    assert setup("classical").suite.evidence_size() == 354
    assert setup("pq").suite.evidence_size() == 7727
    assert setup("classical").suite.fits_in_qr() is True
    assert setup("pq").suite.fits_in_qr() is False
