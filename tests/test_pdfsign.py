"""Signature visible d'un PDF par mise a jour incrementale."""

import shutil
from pathlib import Path

import pytest

from sn import pdfsign
from sn.codec import b45encode

SAMPLE = Path(__file__).parent / "sample.pdf"


@pytest.fixture
def pdf(tmp_path):
    target = tmp_path / "doc.pdf"
    shutil.copy(SAMPLE, target)
    return target


PAYLOAD = bytes(range(256)) * 2


def test_original_bytes_are_preserved(pdf, tmp_path):
    """Le coeur du procede : sans ca, la signature ne vaut plus rien."""
    original = pdf.read_bytes()
    out = tmp_path / "signe.pdf"
    info = pdfsign.embed_qr(pdf, b45encode(PAYLOAD), out)
    assert info["prefix_len"] == len(original)
    assert out.read_bytes()[: len(original)] == original


def test_the_qr_can_be_read_back(pdf, tmp_path):
    out = tmp_path / "signe.pdf"
    pdfsign.embed_qr(pdf, b45encode(PAYLOAD), out)
    assert pdfsign.extract_payload(out) == PAYLOAD


def test_signed_prefix_returns_the_original(pdf, tmp_path):
    original = pdf.read_bytes()
    out = tmp_path / "signe.pdf"
    info = pdfsign.embed_qr(pdf, b45encode(PAYLOAD), out)
    assert pdfsign.signed_prefix(out, info["prefix_len"]) == original


def test_the_pdf_stays_openable(pdf, tmp_path):
    from pypdf import PdfReader
    out = tmp_path / "signe.pdf"
    before = len(PdfReader(str(pdf)).pages)
    pdfsign.embed_qr(pdf, b45encode(PAYLOAD), out)
    assert len(PdfReader(str(out)).pages) == before


@pytest.mark.parametrize("position", pdfsign.POSITIONS)
def test_every_corner_works(pdf, tmp_path, position):
    out = tmp_path / f"{position}.pdf"
    info = pdfsign.embed_qr(pdf, b45encode(PAYLOAD), out, position=position)
    assert info["position"] == position
    assert pdfsign.extract_payload(out) == PAYLOAD


def test_default_is_bottom_right_with_a_10pt_margin(pdf, tmp_path):
    from pypdf import PdfReader
    out = tmp_path / "signe.pdf"
    info = pdfsign.embed_qr(pdf, b45encode(PAYLOAD), out)
    page_w = float(PdfReader(str(pdf)).pages[0].mediabox.width)
    x, y, size = info["box"]
    assert info["position"] == "bottom-right"
    assert y == pytest.approx(10.0)                      # marge basse
    assert page_w - (x + size) == pytest.approx(10.0)    # marge droite


def test_unknown_position_is_refused(pdf, tmp_path):
    with pytest.raises(pdfsign.PdfSignError, match="position inconnue"):
        pdfsign.embed_qr(pdf, b45encode(PAYLOAD), tmp_path / "x.pdf",
                         position="milieu")


def test_page_out_of_range_is_refused(pdf, tmp_path):
    with pytest.raises(pdfsign.PdfSignError, match="page 9"):
        pdfsign.embed_qr(pdf, b45encode(PAYLOAD), tmp_path / "x.pdf", page=8)


def test_oversized_qr_is_refused(pdf, tmp_path):
    with pytest.raises(pdfsign.PdfSignError, match="trop grand"):
        pdfsign.embed_qr(pdf, b45encode(PAYLOAD), tmp_path / "x.pdf", size=5000)


def test_a_pdf_without_a_qr_is_reported(pdf):
    with pytest.raises(pdfsign.PdfSignError, match="aucune preuve"):
        pdfsign.extract_payload(pdf)


def test_bad_prefix_length_is_refused(pdf, tmp_path):
    out = tmp_path / "signe.pdf"
    pdfsign.embed_qr(pdf, b45encode(PAYLOAD), out)
    with pytest.raises(pdfsign.PdfSignError):
        pdfsign.signed_prefix(out, 10**9)
    with pytest.raises(pdfsign.PdfSignError):
        pdfsign.signed_prefix(out, 0)


def test_signing_twice_keeps_both_prefixes_valid(pdf, tmp_path):
    """Une deuxieme signature empile une nouvelle mise a jour."""
    first, second = tmp_path / "1.pdf", tmp_path / "2.pdf"
    a = pdfsign.embed_qr(pdf, b45encode(PAYLOAD), first)
    b = pdfsign.embed_qr(first, b45encode(b"second"), second)
    assert b["prefix_len"] == a["total"]
    assert pdfsign.signed_prefix(second, a["prefix_len"]) == pdf.read_bytes()


# --- contenu ajoute apres la signature (PDF shadow attack) ------------------


def _append_revision(path: Path, text: str = "CONTENU AJOUTE") -> None:
    """Rejoue l'attaque : une revision de plus, par-dessus la page."""
    import io
    from PIL import Image, ImageDraw
    from pypdf import PdfReader, PdfWriter, Transformation

    img = Image.new("RGB", (900, 80), "white")
    ImageDraw.Draw(img).text((5, 5), text, fill="black")
    buf = io.BytesIO(); img.save(buf, format="PDF"); buf.seek(0)
    overlay = PdfReader(buf).pages[0]

    writer = PdfWriter(str(path), incremental=True)
    page = writer.pages[0]
    scale = 300.0 / float(overlay.mediabox.width)
    page.merge_transformed_page(
        overlay, Transformation().scale(scale).translate(80, 700)
    )
    writer.write(str(path))


def test_a_clean_file_has_exactly_one_extra_revision(pdf, tmp_path):
    out = tmp_path / "signe.pdf"
    info = pdfsign.embed_qr(pdf, b45encode(PAYLOAD), out)
    ok, detail = pdfsign.check_tail(out, info["prefix_len"])
    assert ok is True and "conforme" in detail


def test_an_appended_revision_is_detected(pdf, tmp_path):
    """Le coeur de la parade : l'overlay n'est pas signe, mais il se voit."""
    out = tmp_path / "signe.pdf"
    info = pdfsign.embed_qr(pdf, b45encode(PAYLOAD), out)
    before = out.read_bytes()
    _append_revision(out)

    # L'attaquant n'a touche aucun octet signe...
    assert out.read_bytes()[: info["prefix_len"]] == before[: info["prefix_len"]]
    assert pdfsign.signed_prefix(out, info["prefix_len"]) == pdf.read_bytes()
    # ... mais le compte de revisions le trahit.
    ok, detail = pdfsign.check_tail(out, info["prefix_len"])
    assert ok is False and "ajout" in detail


def test_truncated_file_is_detected(pdf, tmp_path):
    out = tmp_path / "signe.pdf"
    info = pdfsign.embed_qr(pdf, b45encode(PAYLOAD), out)
    out.write_bytes(out.read_bytes()[: info["prefix_len"] + 50])
    ok, detail = pdfsign.check_tail(out, info["prefix_len"])
    assert ok is False and "tronque" in detail


def test_count_revisions(pdf, tmp_path):
    out = tmp_path / "signe.pdf"
    before = pdfsign.count_revisions(pdf.read_bytes())
    pdfsign.embed_qr(pdf, b45encode(PAYLOAD), out)
    assert pdfsign.count_revisions(out.read_bytes()) == before + 1
