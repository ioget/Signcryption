"""Unambiguous byte-string encoding, and base45 for QR transport.

The paper writes tuples as ``(x1, ..., xk)`` and requires only that the
encoding be such that "each element can be unequivocally parsed" (p. 2).
That requirement is load-bearing: the hash input on line 18 of the scheme
places the variable-length ``c1`` and ``c2`` next to each other, so a naive
concatenation would let an attacker shift bytes from one field into the
other and obtain a trivial collision.  Every field therefore carries an
explicit 4-byte big-endian length prefix.
"""

from __future__ import annotations

_LEN = 4


def pack(*items: bytes) -> bytes:
    """Encode a tuple of byte strings so that it can be parsed unambiguously."""
    out = bytearray()
    for item in items:
        if len(item) >= 1 << (8 * _LEN):
            raise ValueError("field too long to encode")
        out += len(item).to_bytes(_LEN, "big")
        out += item
    return bytes(out)


def unpack(blob: bytes, count: int | None = None) -> list[bytes]:
    """Inverse of :func:`pack`.  Raises ValueError on any malformed input."""
    out: list[bytes] = []
    i = 0
    while i < len(blob):
        if i + _LEN > len(blob):
            raise ValueError("truncated length prefix")
        n = int.from_bytes(blob[i : i + _LEN], "big")
        i += _LEN
        if i + n > len(blob):
            raise ValueError("truncated field")
        out.append(blob[i : i + n])
        i += n
    if count is not None and len(out) != count:
        raise ValueError(f"expected {count} fields, got {len(out)}")
    return out


# --- base45 (RFC 9285) ------------------------------------------------------
# Maps binary onto the QR alphanumeric charset at 2 bytes -> 3 chars.  Chosen
# over base64 so the payload survives QR alphanumeric mode, and so the evidence
# can also be passed around as plain text when no image decoder is available.

_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_VALUES = {c: i for i, c in enumerate(_ALPHABET)}


def b45encode(data: bytes) -> str:
    out = []
    for i in range(0, len(data) - 1, 2):
        n = data[i] * 256 + data[i + 1]
        n, c = divmod(n, 45)
        e, d = divmod(n, 45)
        out += [_ALPHABET[c], _ALPHABET[d], _ALPHABET[e]]
    if len(data) % 2:
        d, c = divmod(data[-1], 45)
        out += [_ALPHABET[c], _ALPHABET[d]]
    return "".join(out)


def b45decode(text: str) -> bytes:
    try:
        vals = [_VALUES[c] for c in text]
    except KeyError as exc:
        raise ValueError(f"invalid base45 character: {exc.args[0]!r}") from None
    if len(vals) % 3 == 1:
        raise ValueError("invalid base45 length")
    out = bytearray()
    for i in range(0, len(vals) - 2, 3):
        n = vals[i] + vals[i + 1] * 45 + vals[i + 2] * 45 * 45
        if n > 0xFFFF:
            raise ValueError("invalid base45 triple")
        out += n.to_bytes(2, "big")
    if len(vals) % 3 == 2:
        n = vals[-2] + vals[-1] * 45
        if n > 0xFF:
            raise ValueError("invalid base45 pair")
        out.append(n)
    return bytes(out)
