"""QR transport for the evidence payload.

base45 (RFC 9285) maps the binary payload onto the QR alphanumeric
charset, which keeps the code small and leaves the payload printable as
plain text -- so verification still works when no image decoder is
installed.

Decoding uses zxing-cpp.  OpenCV's QRCodeDetector was tried first and
measured at a 10-35% failure rate on codes this dense, at every pixel
scale; zxing-cpp decoded 100/100 at every scale tested, in a tenth of
the install size.
"""

from __future__ import annotations

from pathlib import Path

from .codec import b45decode, b45encode

QR_ALNUM_CAPACITY = 4296  # version 40, error correction level L


class QRTooLarge(ValueError):
    pass


def encode_payload(payload: bytes) -> str:
    return b45encode(payload)


def decode_payload(text: str) -> bytes:
    return b45decode(text.strip())


def write(payload: bytes, path: Path, scale: int = 8) -> dict:
    """Render the payload as a QR image.  Raises QRTooLarge if it will not fit."""
    import segno

    text = encode_payload(payload)
    if len(text) > QR_ALNUM_CAPACITY:
        raise QRTooLarge(
            f"payload is {len(payload)} bytes ({len(text)} chars encoded), "
            f"over the {QR_ALNUM_CAPACITY}-char QR limit"
        )
    qr = segno.make(text, error="m", mode="alphanumeric")
    qr.save(str(path), scale=scale, border=4)
    return {
        "chars": len(text),
        "bytes": len(payload),
        "version": qr.version,
        "error": qr.error,
    }


def read(path: Path) -> bytes:
    """Decode a QR image back to the payload."""
    try:
        import zxingcpp
        from PIL import Image
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "reading QR images needs zxing-cpp and Pillow; "
            "alternatively pass the payload text with --payload"
        ) from exc

    try:
        image = Image.open(path)
    except OSError as exc:
        raise ValueError(f"cannot read image: {path}") from exc

    result = zxingcpp.read_barcode(image)
    if result is None or not result.text:
        raise ValueError(f"no QR code found in {path}")
    return decode_payload(result.text)
