"""Controles sur la zone non signee : rendu et objets actifs."""

import io
import shutil
from pathlib import Path

import pytest

from sn import pdfcheck, pdfsign
from sn.codec import b45encode

SAMPLE = Path(__file__).parent / "sample.pdf"
PAYLOAD = bytes(range(256)) * 2


@pytest.fixture
def signe(tmp_path):
    """Un PDF portant un QR, pose proprement."""
    src = tmp_path / "doc.pdf"
    shutil.copy(SAMPLE, src)
    out = tmp_path / "signe.pdf"
    info = pdfsign.embed_qr(src, b45encode(PAYLOAD), out)
    return out, info["prefix_len"]


def _overlay_page(text: str):
    from PIL import Image, ImageDraw
    from pypdf import PdfReader
    img = Image.new("RGB", (1200, 90), "white")
    ImageDraw.Draw(img).text((5, 5), text, fill="black")
    buf = io.BytesIO(); img.save(buf, format="PDF"); buf.seek(0)
    return PdfReader(buf).pages[0]


def _append(path: Path, *, banner: str = None, js: bool = False,
            attachment: bool = False, link: bool = False) -> None:
    from pypdf import PdfWriter, Transformation
    from pypdf.actions import JavaScript
    from pypdf.generic import (ArrayObject, DictionaryObject, FloatObject,
                               NameObject, NumberObject, TextStringObject)
    w = PdfWriter(str(path), incremental=True)
    page = w.pages[0]
    if banner:
        ov = _overlay_page(banner)
        page.merge_transformed_page(
            ov, Transformation().scale(300.0 / float(ov.mediabox.width)).translate(80, 700))
    if js:
        w.add_open_action(JavaScript("app.alert('x');"))
    if attachment:
        w.add_attachment("charge.bin", b"\x00utile")
    if link:
        annot = DictionaryObject({
            NameObject("/Type"): NameObject("/Annot"),
            NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): ArrayObject([FloatObject(70), FloatObject(600),
                                              FloatObject(520), FloatObject(760)]),
            NameObject("/Border"): ArrayObject(
                [NumberObject(0), NumberObject(0), NumberObject(0)]),
            NameObject("/A"): DictionaryObject({
                NameObject("/S"): NameObject("/URI"),
                NameObject("/URI"): TextStringObject("https://phishing.example"),
            }),
        })
        page[NameObject("/Annots")] = ArrayObject([w._add_object(annot)])
    w.write(str(path))


# --- rendu ------------------------------------------------------------------


def test_a_clean_file_only_differs_where_the_qr_is(signe):
    path, n = signe
    ok, detail = pdfcheck.check_visual(path, n)
    assert ok is True and "zone du QR" in detail


def test_rendering_is_deterministic(signe):
    """Sans cela, la comparaison produirait des faux positifs."""
    path, n = signe
    data = path.read_bytes()
    a = pdfcheck._render(data)
    b = pdfcheck._render(data)
    from PIL import ImageChops
    assert ImageChops.difference(a, b).getbbox() is None


def test_a_banner_outside_the_qr_is_caught(signe):
    path, n = signe
    _append(path, banner="PIRATE INCONNU")
    ok, detail = pdfcheck.check_visual(path, n)
    assert ok is False and "hors de la zone du QR" in detail


def test_a_banner_in_the_same_revision_as_the_qr_is_caught(tmp_path):
    """L'attaque qui passe le compte de revisions."""
    import segno
    from PIL import Image
    from pypdf import PdfReader, PdfWriter, Transformation

    src = tmp_path / "doc.pdf"; shutil.copy(SAMPLE, src)
    propre = tmp_path / "propre.pdf"
    info = pdfsign.embed_qr(src, b45encode(PAYLOAD), propre)

    png = io.BytesIO()
    segno.make(b45encode(PAYLOAD), error="m").save(png, kind="png", scale=6, border=2)
    png.seek(0)
    b = io.BytesIO(); Image.open(png).convert("1").save(b, format="PDF"); b.seek(0)
    qr_page = PdfReader(b).pages[0]

    fusion = tmp_path / "fusion.pdf"
    w = PdfWriter(str(src), incremental=True)
    page = w.pages[0]
    pw = float(page.mediabox.width)
    page.merge_transformed_page(
        qr_page, Transformation().scale(100.0 / float(qr_page.mediabox.width))
        .translate(pw - 110, 10))
    ov = _overlay_page("PIRATE INCONNU")
    page.merge_transformed_page(
        ov, Transformation().scale(300.0 / float(ov.mediabox.width)).translate(80, 700))
    w.write(str(fusion))

    # le compte de revisions, lui, est conforme
    assert pdfsign.check_tail(fusion, info["prefix_len"])[0] is True
    # mais le rendu trahit l'ajout
    assert pdfcheck.check_visual(fusion, info["prefix_len"])[0] is False


def test_a_page_resized_after_signing_is_caught(signe):
    from pypdf import PdfWriter
    path, n = signe
    w = PdfWriter(str(path), incremental=True)
    w.pages[0].mediabox.upper_right = (400, 500)
    w.write(str(path))
    ok, detail = pdfcheck.check_visual(path, n)
    assert ok is False


# --- objets actifs ----------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        ({"js": True}, "/JavaScript"),
        ({"link": True}, "/Annots"),
        ({"attachment": True}, "/EmbeddedFiles"),
    ],
)
def test_injected_objects_are_caught(signe, kwargs, expected):
    """Invisibles au rendu, donc c'est ce controle qui doit les voir."""
    path, n = signe
    _append(path, **kwargs)
    assert pdfcheck.check_visual(path, n)[0] is True     # rien ne se voit
    ok, detail = pdfcheck.check_objects(path, n)
    assert ok is False and expected in detail


def test_a_clean_file_adds_no_active_object(signe):
    path, n = signe
    ok, detail = pdfcheck.check_objects(path, n)
    assert ok is True and "aucun objet actif" in detail


def test_objects_already_present_before_signing_are_allowed(tmp_path):
    """Un document peut legitimement contenir des liens : ce qui compte
    est qu'il n'en apparaisse pas de nouveaux apres signature."""
    src = tmp_path / "doc.pdf"; shutil.copy(SAMPLE, src)
    _append(src, link=True)              # avant signature
    out = tmp_path / "signe.pdf"
    info = pdfsign.embed_qr(src, b45encode(PAYLOAD), out)
    assert pdfcheck.check_objects(out, info["prefix_len"])[0] is True


def test_scan_objects_finds_what_is_there(signe):
    path, n = signe
    _append(path, js=True)
    found = pdfcheck.scan_objects(path.read_bytes())
    assert found["/JavaScript"] >= 1
