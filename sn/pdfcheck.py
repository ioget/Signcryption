"""Deux controles sur la zone non signee d'un PDF.

Les octets ajoutes apres la signature ne peuvent pas etre authentifies :
c'est l'attaquant qui les ecrit.  Mais on sait exactement ce qu'ils ont
le droit de contenir -- l'image du QR, rien d'autre -- et c'est
verifiable sans rien stocker ni demander a l'utilisateur.

`check_visual`  : le rendu de la page ne doit differer de celui du
                  prefixe signe que dans la zone du QR lui-meme.
`check_objects` : la revision ajoutee ne doit introduire aucun objet
                  actif (JavaScript, lien, piece jointe, formulaire...).

Le premier attrape ce qui se voit, le second ce qui ne se voit pas.
"""

from __future__ import annotations

import io
from collections import Counter
from pathlib import Path

# Objets qui agissent sur le lecteur ou transportent des donnees, et qui
# n'ont aucune raison d'apparaitre dans la revision qui pose un QR.
DANGEROUS_KEYS = frozenset({
    "/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/URI",
    "/EmbeddedFile", "/EmbeddedFiles", "/Annots", "/AcroForm", "/XFA",
    "/GoToR", "/GoToE", "/SubmitForm", "/ImportData", "/RichMedia",
    "/Movie", "/Sound", "/Rendition",
})

# Echelles de rendu essayees successivement.  La premiere suffit presque
# toujours ; un petit QR demande plus de pixels par module pour que le
# decodeur sache le localiser.
RENDER_SCALES = (2.0, 4.0)
# Tolerance sur un canal 0-255, pour absorber l'anticrenelage.
PIXEL_THRESHOLD = 16
# La zone de difference doit tenir dans le QR detecte, elargi d'autant :
# l'image inseree porte une bordure blanche que le decodeur ne compte pas.
QR_BOX_SLACK = 0.30


class CheckError(Exception):
    pass


# --- objets -----------------------------------------------------------------


def _walk(obj, found: Counter, seen: set, depth: int = 0) -> None:
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject

    if depth > 60:
        return
    if isinstance(obj, IndirectObject):
        if obj.idnum in seen:
            return
        seen.add(obj.idnum)
        try:
            obj = obj.get_object()
        except Exception:
            return
        _walk(obj, found, seen, depth + 1)
    elif isinstance(obj, DictionaryObject):
        for key, value in obj.items():
            name = str(key)
            if name in DANGEROUS_KEYS:
                found[name] += 1
            _walk(value, found, seen, depth + 1)
    elif isinstance(obj, ArrayObject):
        for value in obj:
            _walk(value, found, seen, depth + 1)


def scan_objects(data: bytes) -> Counter:
    """Compte les cles sensibles dans tous les objets atteignables."""
    from pypdf import PdfReader
    from pypdf.generic import IndirectObject

    found: Counter = Counter()
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
    except Exception as exc:
        raise CheckError(f"PDF illisible : {exc}") from exc

    seen: set = set()
    for gen, table in (reader.xref or {}).items():
        for num in list(table):
            try:
                _walk(IndirectObject(num, gen, reader), found, seen)
            except Exception:
                continue
    _walk(reader.trailer, found, seen)
    return found


def check_objects(pdf: Path, prefix_len: int) -> tuple[bool, str]:
    """Refuse toute cle sensible que la revision ajoutee aurait introduite.

    On compare au prefixe signe plutot que d'interdire dans l'absolu :
    un document peut legitimement contenir des liens avant signature, ce
    qui compte est qu'il n'en apparaisse pas de nouveaux apres.
    """
    data = Path(pdf).read_bytes()
    before = scan_objects(data[:prefix_len])
    after = scan_objects(data)

    added = {k: after[k] - before.get(k, 0) for k in after if after[k] > before.get(k, 0)}
    if not added:
        return True, "aucun objet actif ajoute"
    detail = ", ".join(f"{k} x{n}" for k, n in sorted(added.items()))
    return False, f"objets ajoutes apres signature : {detail}"


# --- rendu ------------------------------------------------------------------


def _render(data: bytes, page: int = 0, scale: float = RENDER_SCALES[0]):
    import pypdfium2 as pdfium

    doc = pdfium.PdfDocument(data)
    try:
        return doc[page].render(scale=scale).to_pil().convert("L")
    finally:
        doc.close()


def _qr_box(image):
    """Bounding box du QR dans l'image, telle que le decodeur la voit."""
    import zxingcpp

    result = zxingcpp.read_barcode(image.convert("RGB"))
    if result is None:
        return None
    p = result.position
    xs = [p.top_left.x, p.top_right.x, p.bottom_left.x, p.bottom_right.x]
    ys = [p.top_left.y, p.top_right.y, p.bottom_left.y, p.bottom_right.y]
    return min(xs), min(ys), max(xs), max(ys)


def _inflate(box, factor: float, bounds):
    x0, y0, x1, y1 = box
    dx, dy = (x1 - x0) * factor / 2, (y1 - y0) * factor / 2
    return (
        max(0, x0 - dx), max(0, y0 - dy),
        min(bounds[0], x1 + dx), min(bounds[1], y1 + dy),
    )


def check_visual(pdf: Path, prefix_len: int, page: int = 0) -> tuple[bool, str]:
    """Le rendu ne doit differer du prefixe signe que la ou est le QR.

    Rien n'est stocke ni suppose : la zone autorisee est celle du QR tel
    que le decodeur le localise dans la page, donc un attaquant ne peut
    pas l'elargir en trafiquant la preuve.
    """
    from PIL import ImageChops

    data = Path(pdf).read_bytes()
    last = "QR introuvable dans le rendu de la page"

    for scale in RENDER_SCALES:
        try:
            signed = _render(data[:prefix_len], page, scale)
            shown = _render(data, page, scale)
        except Exception as exc:
            raise CheckError(f"rendu impossible : {exc}") from exc

        if signed.size != shown.size:
            return False, "la taille de la page a change apres signature"

        mask = ImageChops.difference(signed, shown).point(
            lambda v: 255 if v > PIXEL_THRESHOLD else 0
        )
        changed = mask.getbbox()
        if changed is None:
            return False, "aucun QR visible sur la page"

        box = _qr_box(shown)
        if box is None:
            # Un QR trop petit n'est pas localisable a cette echelle :
            # on reessaie plus finement avant d'abandonner.
            continue
        allowed = _inflate(box, QR_BOX_SLACK, shown.size)

        if (
            changed[0] >= allowed[0] and changed[1] >= allowed[1]
            and changed[2] <= allowed[2] and changed[3] <= allowed[3]
        ):
            return True, "le rendu ne differe que dans la zone du QR"

        return False, (
            "le rendu a change hors de la zone du QR "
            f"(difference {tuple(int(v) for v in changed)}, "
            f"QR {tuple(int(v) for v in allowed)})"
        )

    return False, last
