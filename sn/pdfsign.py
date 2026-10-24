"""Signature visible d'un PDF, sans casser le controle d'integrite.

Le probleme : signer un PDF puis y coller le QR code modifie le fichier,
donc la signature ne verifie plus.

La solution : une mise a jour incrementale.  Le format PDF permet
d'ajouter des objets a la FIN d'un fichier sans toucher un seul octet de
ce qui precede.  On signe donc les N octets du PDF d'origine, puis on
appende le QR ; le prefixe de N octets reste intact au bit pres.

    [──── PDF original, N octets ────][──── ajout : image QR ────]
     \________ c'est ce qui est signe ________/

A l'affichage, le lecteur suit le dernier xref et voit le QR a sa place
sur la page : la position dans le fichier n'a rien a voir avec la
position sur la page.

Limite connue, a traiter par l'appelant : la partie situee apres N n'est
pas signee.  Elle peut en principe recouvrir visuellement le contenu
d'origine (PDF shadow attack).  C'est pourquoi la verification extrait
le prefixe signe dans un fichier a part : c'est celui-la qui fait foi,
pas celui qu'on vous a remis.
"""

from __future__ import annotations

import io
from pathlib import Path

from .codec import b45decode

# Coordonnees PDF : origine en bas a gauche, unite le point (1/72 pouce).
POSITIONS = ("bottom-right", "bottom-left", "top-right", "top-left")
DEFAULT_POSITION = "bottom-right"
DEFAULT_MARGIN = 10.0
DEFAULT_SIZE = 100.0

# 1 bit par pixel : un QR n'a que deux couleurs, et l'image pese alors
# ~10 Kio au lieu de ~170 Kio en RGB.
_PNG_SCALE = 6
_PNG_BORDER = 2


class PdfSignError(Exception):
    pass


def _qr_page(payload_text: str):
    """Le QR comme page PDF d'un seul XObject image, donc re-extractible."""
    import segno
    from PIL import Image
    from pypdf import PdfReader

    png = io.BytesIO()
    segno.make(payload_text, error="m").save(
        png, kind="png", scale=_PNG_SCALE, border=_PNG_BORDER
    )
    png.seek(0)
    pdf = io.BytesIO()
    Image.open(png).convert("1").save(pdf, format="PDF")
    pdf.seek(0)
    return PdfReader(pdf).pages[0]


def _corner(
    position: str, page_w: float, page_h: float, size: float, margin: float
) -> tuple[float, float]:
    if position not in POSITIONS:
        raise PdfSignError(
            f"position inconnue {position!r} ; choisis parmi {', '.join(POSITIONS)}"
        )
    right = page_w - margin - size
    top = page_h - margin - size
    return {
        "bottom-right": (right, margin),
        "bottom-left": (margin, margin),
        "top-right": (right, top),
        "top-left": (margin, top),
    }[position]


def embed_qr(
    source: Path,
    payload_text: str,
    out: Path,
    *,
    page: int = 0,
    position: str = DEFAULT_POSITION,
    margin: float = DEFAULT_MARGIN,
    size: float = DEFAULT_SIZE,
) -> dict:
    """Ajoute le QR au PDF en preservant ses octets d'origine.

    Renvoie de quoi rendre compte, et verifie lui-meme que le prefixe est
    bien intact : si une version de pypdf cessait d'ecrire en
    incremental, la signature deviendrait silencieusement invalide.
    """
    from pypdf import PdfReader, PdfWriter, Transformation

    source, out = Path(source), Path(out)
    original = source.read_bytes()
    n = len(original)

    qr_page = _qr_page(payload_text)
    writer = PdfWriter(str(source), incremental=True)
    if not 0 <= page < len(writer.pages):
        raise PdfSignError(
            f"page {page + 1} demandee, le document en a {len(writer.pages)}"
        )
    target = writer.pages[page]
    page_w = float(target.mediabox.width)
    page_h = float(target.mediabox.height)
    if size + 2 * margin > min(page_w, page_h):
        raise PdfSignError("le QR est trop grand pour la page")

    x, y = _corner(position, page_w, page_h, size, margin)
    scale = size / float(qr_page.mediabox.width)
    target.merge_transformed_page(
        qr_page, Transformation().scale(scale).translate(x, y)
    )
    writer.write(str(out))

    produced = out.read_bytes()
    if produced[:n] != original:
        out.unlink(missing_ok=True)
        raise PdfSignError(
            "l'ecriture n'a pas preserve les octets d'origine ; "
            "la signature serait invalide, rien n'a ete ecrit"
        )
    added_revisions = count_revisions(produced) - count_revisions(original)
    if added_revisions != 1:
        out.unlink(missing_ok=True)
        raise PdfSignError(
            f"l'incrustation a ajoute {added_revisions} revisions au lieu "
            "d'une seule ; la verification les refuserait"
        )
    del PdfReader
    return {
        "prefix_len": n,
        "total": len(produced),
        "added": len(produced) - n,
        "page": page + 1,
        "pages": len(writer.pages),
        "position": position,
        "box": (x, y, size),
    }


def count_revisions(data: bytes) -> int:
    """Nombre de revisions du fichier.

    Chaque mise a jour incrementale se termine par son propre %%EOF, donc
    les compter revient a compter les revisions.
    """
    return data.count(b"%%EOF")


def check_tail(pdf: Path, prefix_len: int) -> tuple[bool, str]:
    """Verifie que rien n'a ete ajoute apres l'incrustation du QR.

    Les octets situes apres prefix_len ne sont pas signes : on ne peut
    pas les authentifier, mais on sait exactement combien de revisions
    ils doivent contenir, à savoir une seule, celle du QR.  Une revision
    de plus signifie que quelqu'un a appende du contenu apres coup --
    typiquement un bandeau qui recouvre le texte d'origine a l'ecran
    (PDF shadow attack).

    Cela n'attrape pas un attaquant qui remplacerait notre revision par
    une seule revision contenant a la fois le QR et son ajout.  La
    garantie forte reste le prefixe extrait par signed_prefix().
    """
    data = Path(pdf).read_bytes()
    if prefix_len <= 0 or prefix_len > len(data):
        return False, f"prefixe annonce incoherent ({prefix_len} octets)"
    expected = count_revisions(data[:prefix_len]) + 1
    found = count_revisions(data)
    if found == expected:
        return True, f"{found} revisions, conforme"
    if found < expected:
        return False, f"{found} revisions au lieu de {expected} : fichier tronque"
    return (
        False,
        f"{found} revisions au lieu de {expected} : "
        f"{found - expected} ajout(s) apres la signature",
    )


def signed_prefix(pdf: Path, prefix_len: int) -> bytes:
    """Les octets reellement couverts par la signature."""
    data = Path(pdf).read_bytes()
    if prefix_len <= 0 or prefix_len > len(data):
        raise PdfSignError(
            f"prefixe annonce de {prefix_len} octets, le fichier en fait {len(data)}"
        )
    return data[:prefix_len]


def extract_payload(pdf: Path) -> bytes:
    """Relit la preuve depuis le QR incruste dans le PDF."""
    import zxingcpp
    from pypdf import PdfReader

    reader = PdfReader(str(pdf))
    for page in reader.pages:
        try:
            images = list(page.images)
        except Exception:  # page sans ressource image exploitable
            continue
        for image in images:
            try:
                result = zxingcpp.read_barcode(image.image)
            except Exception:
                continue
            if result and result.text:
                try:
                    return b45decode(result.text.strip())
                except ValueError:
                    continue  # un autre code-barres, pas notre preuve
    raise PdfSignError(f"aucune preuve SN trouvee dans {pdf}")
