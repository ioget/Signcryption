"""Mode chiffre : signcryption complete vers un destinataire precis."""

import pytest

from sn.evidence import Metadata, build_message, split_message
from sn.scheme import gen_rcv, sc
from sn.sealed import Sealed

DOC = b"RAPPORT CONFIDENTIEL\nBudget : 12500 EUR\n"


@pytest.fixture
def sealed(party):
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    meta = Metadata.now("rapport.txt", "Rosly", "Rapport", "No 1")
    C = sc(dp, sk_sd, pk_rcv, build_message(meta, DOC))
    return Sealed(dp=dp, meta=meta, pk_sd=pk_sd, pk_rcv=pk_rcv, C=C), sk_rcv


def test_the_recipient_recovers_the_document(sealed):
    s, sk_rcv = sealed
    assert s.open(sk_rcv) == DOC


def test_the_document_is_not_in_the_file(sealed, party):
    """La difference avec le mode QR : c2 est reellement transporte."""
    s, _ = sealed
    blob = s.to_bytes()
    assert DOC not in blob
    assert b"12500" not in blob and b"CONFIDENTIEL" not in blob


def test_nobody_else_can_open_it(sealed, party):
    s, _ = sealed
    other_sk, _ = gen_rcv(party[0])
    assert s.open(other_sk) is None


def test_serialisation_roundtrip(sealed):
    s, sk_rcv = sealed
    back = Sealed.from_bytes(s.to_bytes())
    assert back.meta == s.meta and back.pk_sd == s.pk_sd
    assert back.open(sk_rcv) == DOC


@pytest.mark.parametrize("field", ["t", "sigma", "c1", "c2"])
def test_tampering_is_refused(sealed, field):
    from sn.scheme import Ciphertext
    s, sk_rcv = sealed
    broken = bytearray(getattr(s.C, field)); broken[0] ^= 0x01
    forged = Sealed(**{**s.__dict__,
                       "C": Ciphertext(**{**s.C.__dict__, field: bytes(broken)})})
    assert forged.open(sk_rcv) is None


def test_truncated_file_is_refused(sealed):
    s, _ = sealed
    with pytest.raises(ValueError):
        Sealed.from_bytes(s.to_bytes()[:-20])


def test_unknown_version_is_refused(sealed):
    s, _ = sealed
    blob = bytearray(s.to_bytes()); blob[4] = 99
    with pytest.raises(ValueError, match="version"):
        Sealed.from_bytes(bytes(blob))


# --- non-repudiation --------------------------------------------------------


def test_evidence_lets_a_third_party_establish_the_origin(sealed):
    """PV : l'arbitre n'a aucun secret, et l'expediteur n'a rien a fournir."""
    s, sk_rcv = sealed
    nr = s.evidence(sk_rcv)
    assert nr is not None
    assert s.check(DOC, nr) is True


def test_a_different_document_is_refused_by_the_arbiter(sealed):
    s, sk_rcv = sealed
    nr = s.evidence(sk_rcv)
    assert s.check(b"Budget : 99000 EUR\n", nr) is False


def test_evidence_of_one_message_does_not_prove_another(party):
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    out = []
    for text in (b"premier", b"second"):
        meta = Metadata.now("f.txt", "Rosly")
        C = sc(dp, sk_sd, pk_rcv, build_message(meta, text))
        out.append(Sealed(dp=dp, meta=meta, pk_sd=pk_sd, pk_rcv=pk_rcv, C=C))
    nr_premier = out[0].evidence(sk_rcv)
    assert out[1].check(b"second", nr_premier) is False


def test_metadata_is_bound_to_the_document(sealed):
    s, sk_rcv = sealed
    nr = s.evidence(sk_rcv)
    forged = Sealed(**{**s.__dict__,
                       "meta": Metadata(s.meta.timestamp, s.meta.filename,
                                        "Quelqu'un d'autre", s.meta.title,
                                        s.meta.reference)})
    assert forged.check(DOC, nr) is False


def test_split_message_is_the_inverse_of_build_message():
    meta = Metadata.now("f.txt", "Rosly", "Titre", "No 1")
    back_meta, back_doc = split_message(build_message(meta, DOC))
    assert back_meta == meta and back_doc == DOC
