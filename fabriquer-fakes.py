#!/usr/bin/env python3
"""Fabrique les versions falsifiees d'un PDF signe.

    .venv/bin/python fabriquer-fakes.py <pdf-signe> [pdf-original]

Les manipulations binaires (retourner un bit, appender une revision,
tronquer, recoller un QR) n'ont pas d'equivalent en ligne de commande :
c'est ce que fait ce script.  Chaque fake est ecrit a la racine.
"""
import io
import shutil
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from pypdf import PdfReader, PdfWriter, Transformation

from sn import pdfsign, qr
from sn.evidence import Evidence

ROOT = Path(__file__).resolve().parent


def _font(size):
    try:
        return ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf", size)
    except OSError:
        return ImageFont.load_default()


def append_revision(path: Path, lines, at=(80, 745)) -> None:
    """Ajoute une revision incrementale : aucun octet signe n'est touche."""
    img = Image.new("RGB", (1400, 52 * len(lines) + 20), "white")
    draw = ImageDraw.Draw(img)
    for i, line in enumerate(lines):
        draw.text((8, 8 + 52 * i), line, fill="black", font=_font(44))
    buf = io.BytesIO(); img.save(buf, format="PDF"); buf.seek(0)
    overlay = PdfReader(buf).pages[0]

    writer = PdfWriter(str(path), incremental=True)
    page = writer.pages[0]
    page.merge_transformed_page(
        overlay,
        Transformation().scale(300.0 / float(overlay.mediabox.width)).translate(*at),
    )
    writer.write(str(path))


def main() -> int:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    signe_path = Path(sys.argv[1])
    original = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "letter_attestation_rang.pdf"
    signe = signe_path.read_bytes()
    n = Evidence.from_bytes(pdfsign.extract_payload(signe_path)).prefix_len
    print(f"source : {signe_path.name} — {len(signe)} octets, dont {n} signes\n")

    # 1 — un bit retourne au milieu de la zone signee
    data = bytearray(signe); data[n // 2] ^= 0x01
    (ROOT / "fake-1-octet.pdf").write_bytes(bytes(data))

    # 2 — bandeau ajoute par-dessus, en revision incrementale
    shutil.copy(signe_path, ROOT / "fake-2-overlay.pdf")
    append_revision(ROOT / "fake-2-overlay.pdf",
                    ["PIRATE INCONNU", "Matricule : 99X999ZZ"])

    # 3 — fichier coupe juste apres la zone signee
    (ROOT / "fake-3-tronque.pdf").write_bytes(signe[: n + 200])

    # 4 — l'original modifie AVANT signature, puis le QR du vrai recolle
    data = bytearray(original.read_bytes()); data[60000:60010] = b"MODIFIE!!!"
    (ROOT / "fake-original-modifie.pdf").write_bytes(bytes(data))
    pdfsign.embed_qr(
        ROOT / "fake-original-modifie.pdf",
        qr.encode_payload(pdfsign.extract_payload(signe_path)),
        ROOT / "fake-4-original-modifie-signe.pdf",
    )

    # 6 — QR + bandeau dans UNE SEULE revision : le compte reste conforme
    import segno
    from PIL import Image as PILImage
    payload = qr.encode_payload(pdfsign.extract_payload(signe_path))
    png = io.BytesIO()
    segno.make(payload, error="m").save(png, kind="png", scale=6, border=2)
    png.seek(0)
    buf = io.BytesIO()
    PILImage.open(png).convert("1").save(buf, format="PDF")
    buf.seek(0)
    qr_page = PdfReader(buf).pages[0]

    def _fusion(out_name, with_js=False, with_banner=False):
        w = PdfWriter(str(original), incremental=True)
        page = w.pages[0]
        pw = float(page.mediabox.width)
        page.merge_transformed_page(
            qr_page,
            Transformation().scale(100.0 / float(qr_page.mediabox.width))
            .translate(pw - 110, 10),
        )
        if with_banner:
            img = Image.new("RGB", (1400, 120), "white")
            d = ImageDraw.Draw(img)
            d.text((8, 8), "PIRATE INCONNU", fill="black", font=_font(44))
            d.text((8, 60), "Matricule : 99X999ZZ", fill="black", font=_font(44))
            c = io.BytesIO(); img.save(c, format="PDF"); c.seek(0)
            ov = PdfReader(c).pages[0]
            page.merge_transformed_page(
                ov, Transformation().scale(300.0 / float(ov.mediabox.width))
                .translate(80, 745))
        if with_js:
            from pypdf.actions import JavaScript
            w.add_open_action(JavaScript("app.launchURL('https://phishing.example');"))
        w.write(str(ROOT / out_name))

    _fusion("fake-6-fusion-bandeau.pdf", with_banner=True)
    _fusion("fake-7-fusion-javascript.pdf", with_js=True)

    # 8, 9, 10 — injections invisibles ajoutees en revision separee
    from pypdf.actions import JavaScript
    from pypdf.generic import (ArrayObject, DictionaryObject, FloatObject,
                               NameObject, NumberObject, TextStringObject)
    shutil.copy(signe_path, ROOT / "fake-8-javascript.pdf")
    w = PdfWriter(str(ROOT / "fake-8-javascript.pdf"), incremental=True)
    w.add_open_action(JavaScript("app.alert('compromis');"))
    w.write(str(ROOT / "fake-8-javascript.pdf"))

    shutil.copy(signe_path, ROOT / "fake-9-lien-invisible.pdf")
    w = PdfWriter(str(ROOT / "fake-9-lien-invisible.pdf"), incremental=True)
    page = w.pages[0]
    annot = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([FloatObject(70), FloatObject(600),
                                          FloatObject(520), FloatObject(760)]),
        NameObject("/Border"): ArrayObject(
            [NumberObject(0), NumberObject(0), NumberObject(0)]),
        NameObject("/A"): DictionaryObject({
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject("https://phishing.example/paiement"),
        }),
    })
    page[NameObject("/Annots")] = ArrayObject([w._add_object(annot)])
    w.write(str(ROOT / "fake-9-lien-invisible.pdf"))

    shutil.copy(signe_path, ROOT / "fake-10-piece-jointe.pdf")
    w = PdfWriter(str(ROOT / "fake-10-piece-jointe.pdf"), incremental=True)
    w.add_attachment("facture.exe", b"MZ\x90\x00charge utile")
    w.write(str(ROOT / "fake-10-piece-jointe.pdf"))

    # 5 — certificat dont les en-tetes lisibles sont maquilles
    cert = ROOT / "fatou-certificat-public.pem"
    if cert.exists():
        (ROOT / "fake-5-certificat.pem").write_text(
            cert.read_text()
            .replace("Name: Fatou Ndiaye", "Name: Directrice Generale")
            .replace("Role: Doctorante", "Role: Directrice")
        )

    print("fakes produits :")
    for p in sorted(ROOT.glob("fake-*")):
        print(f"  {p.name:36s} {p.stat().st_size:>8} octets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
