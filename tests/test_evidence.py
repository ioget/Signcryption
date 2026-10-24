"""Evidence record, QR transport, and the recomputed-c2 trick."""

import os

import pytest

from sn import qr
from sn.evidence import Evidence, Metadata, build_message
from sn.scheme import n, sc


def make_evidence(party, document: bytes, filename="doc.txt"):
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    meta = Metadata.now(filename=filename, signer="Tester")
    m = build_message(meta, document)
    C = sc(dp, sk_sd, pk_rcv, m)
    nr = n(dp, sk_rcv, pk_sd, C)
    return Evidence(
        dp=dp, meta=meta, pk_sd=pk_sd, pk_rcv=pk_rcv,
        c1=C.c1, sigma=C.sigma, t=C.t, nr=nr,
    )


def test_evidence_verifies_the_original(party):
    doc = b"the original document"
    assert make_evidence(party, doc).verify(doc) is True


def test_evidence_rejects_a_modified_document(party):
    doc = b"the original document"
    ev = make_evidence(party, doc)
    assert ev.verify(b"the modified document") is False
    assert ev.verify(doc + b" ") is False
    assert ev.verify(b"") is False


def test_payload_size_is_independent_of_document_size(party):
    """c2 is not in the payload; that is what makes a QR code possible."""
    small = len(make_evidence(party, b"x").to_bytes())
    large = len(make_evidence(party, os.urandom(100_000)).to_bytes())
    assert small == large


def test_evidence_serialisation_roundtrip(party):
    ev = make_evidence(party, b"hello")
    back = Evidence.from_bytes(ev.to_bytes())
    assert back.meta == ev.meta
    assert back.nr == ev.nr
    assert back.dp.tau0 == ev.dp.tau0
    assert back.dp.suite.name == ev.dp.suite.name
    assert back.verify(b"hello") is True


def test_metadata_is_bound_to_the_document(party):
    """Metadata rides inside m, so altering it breaks the signature."""
    ev = make_evidence(party, b"hello")
    forged = Evidence(
        dp=ev.dp,
        meta=Metadata(ev.meta.timestamp, ev.meta.filename, "Someone Else"),
        pk_sd=ev.pk_sd, pk_rcv=ev.pk_rcv,
        c1=ev.c1, sigma=ev.sigma, t=ev.t, nr=ev.nr,
    )
    assert forged.verify(b"hello") is False


def test_evidence_rejects_corrupt_payloads(party):
    blob = make_evidence(party, b"hello").to_bytes()
    with pytest.raises(ValueError):
        Evidence.from_bytes(blob[:-5])
    with pytest.raises(ValueError):
        Evidence.from_bytes(b"\x00\x00\x00\x01\x09" + blob[5:])  # bad version


def test_classical_evidence_fits_a_qr_code(tmp_path, party):
    dp = party[0]
    if dp.suite.name != "classical":
        pytest.skip("PQ uses a sidecar file")
    ev = make_evidence(party, b"a document of some length" * 40)
    out = tmp_path / "ev.png"
    info = qr.write(ev.to_bytes(), out)
    assert out.exists() and info["chars"] < qr.QR_ALNUM_CAPACITY


def test_pq_evidence_does_not_fit_a_qr_code(tmp_path, party):
    dp = party[0]
    if dp.suite.name != "pq":
        pytest.skip("classical fits")
    ev = make_evidence(party, b"x")
    with pytest.raises(qr.QRTooLarge):
        qr.write(ev.to_bytes(), tmp_path / "ev.png")


def test_qr_image_roundtrip(tmp_path, party):
    """Write a real PNG, read it back, and verify through it."""
    dp = party[0]
    if dp.suite.name != "classical":
        pytest.skip("PQ uses a sidecar file")
    doc = b"contract text that must not change"
    ev = make_evidence(party, doc)
    out = tmp_path / "ev.png"
    qr.write(ev.to_bytes(), out)
    recovered = Evidence.from_bytes(qr.read(out))
    assert recovered.verify(doc) is True
    assert recovered.verify(doc + b"!") is False


def test_qr_decoding_is_reliable(tmp_path, party):
    """Guards a real regression.

    OpenCV's QRCodeDetector silently failed to decode codes of this
    density 10-35% of the time, which made verification non-deterministic.
    Repeated here so a decoder swap cannot quietly reintroduce it.
    """
    dp = party[0]
    if dp.suite.name != "classical":
        pytest.skip("PQ uses a sidecar file")
    doc = b"a contract with enough text to fill the code" * 5
    for _ in range(15):
        ev = make_evidence(party, doc)  # fresh keys and nonce each time
        out = tmp_path / "ev.png"
        qr.write(ev.to_bytes(), out)
        assert Evidence.from_bytes(qr.read(out)).verify(doc) is True


# --- titre et numero d'ordre ------------------------------------------------


def test_title_and_reference_survive_the_roundtrip(party):
    ev = make_evidence(party, b"contenu")
    from sn.evidence import Metadata
    full = Evidence(**{**ev.__dict__, "meta": Metadata(
        ev.meta.timestamp, ev.meta.filename, ev.meta.signer,
        "Contrat de prestation", "2026-001",
    )})
    back = Evidence.from_bytes(full.to_bytes())
    assert back.meta.title == "Contrat de prestation"
    assert back.meta.reference == "2026-001"


def _signed_with(party, document, title, reference):
    from sn.evidence import Metadata
    from sn.scheme import n, sc
    dp, sk_sd, pk_sd, sk_rcv, pk_rcv = party
    meta = Metadata.now("doc.txt", "Tester", title, reference)
    m = build_message(meta, document)
    C = sc(dp, sk_sd, pk_rcv, m)
    return Evidence(
        dp=dp, meta=meta, pk_sd=pk_sd, pk_rcv=pk_rcv,
        c1=C.c1, sigma=C.sigma, t=C.t, nr=n(dp, sk_rcv, pk_sd, C),
    )


def test_changing_the_title_breaks_the_signature(party):
    """Le titre est dans m, donc la signature le couvre."""
    from sn.evidence import Metadata
    ev = _signed_with(party, b"contenu", "Contrat de prestation", "2026-001")
    assert ev.verify(b"contenu") is True
    forged = Evidence(**{**ev.__dict__, "meta": Metadata(
        ev.meta.timestamp, ev.meta.filename, ev.meta.signer,
        "Facture acquittee", ev.meta.reference,
    )})
    assert forged.verify(b"contenu") is False


def test_changing_the_order_number_breaks_the_signature(party):
    from sn.evidence import Metadata
    ev = _signed_with(party, b"contenu", "Contrat", "2026-001")
    forged = Evidence(**{**ev.__dict__, "meta": Metadata(
        ev.meta.timestamp, ev.meta.filename, ev.meta.signer,
        ev.meta.title, "2026-999",
    )})
    assert forged.verify(b"contenu") is False


def test_title_and_reference_are_optional(party):
    ev = _signed_with(party, b"contenu", "", "")
    assert ev.verify(b"contenu") is True
    assert Evidence.from_bytes(ev.to_bytes()).meta.title == ""
