"""Encodage PEM avec en-tetes lisibles (style RFC 1421).

Un bloc ressemble a ceci :

    -----BEGIN SN CERTIFICATE-----
    Name: Rosly Mamakem
    Email: rosly@ugb.sn

    <base64 du corps>
    -----END SN CERTIFICATE-----

ATTENTION : les en-tetes sont hors du base64, donc ils ne sont PAS
couverts par la signature.  Ils servent a lire le fichier a l'oeil nu.
La verite est dans le corps signe ; `verify_headers` sert a reperer un
fichier dont les en-tetes ont ete maquilles.
"""

from __future__ import annotations

import base64
import re

_BEGIN = "-----BEGIN {tag}-----"
_END = "-----END {tag}-----"
_LINE = 64

_BLOCK = re.compile(
    r"-----BEGIN (?P<tag>[A-Z0-9 ]+)-----\s*\n(?P<content>.*?)-----END (?P=tag)-----",
    re.DOTALL,
)


class PemError(ValueError):
    pass


def _check_header(key: str, value: str) -> None:
    if ":" in key or "\n" in key or not key.strip():
        raise PemError(f"nom d'en-tete invalide : {key!r}")
    if "\n" in value or "\r" in value:
        raise PemError(f"valeur d'en-tete multi-ligne interdite : {key}")


def encode(tag: str, headers: dict[str, str], body: bytes) -> str:
    """Construit un bloc PEM."""
    lines = [_BEGIN.format(tag=tag)]
    for key, value in headers.items():
        _check_header(key, value)
        lines.append(f"{key}: {value}")
    if headers:
        lines.append("")
    b64 = base64.b64encode(body).decode("ascii")
    lines += [b64[i : i + _LINE] for i in range(0, len(b64), _LINE)]
    lines.append(_END.format(tag=tag))
    return "\n".join(lines) + "\n"


def decode_all(text: str) -> list[tuple[str, dict[str, str], bytes]]:
    """Renvoie tous les blocs du fichier, dans l'ordre."""
    out = []
    for match in _BLOCK.finditer(text):
        headers: dict[str, str] = {}
        payload: list[str] = []
        in_body = False
        for line in match.group("content").splitlines():
            stripped = line.strip()
            if not in_body:
                if not stripped:
                    in_body = True
                    continue
                if ":" in stripped and not _looks_like_base64(stripped):
                    key, _, value = stripped.partition(":")
                    headers[key.strip()] = value.strip()
                    continue
                in_body = True
            if stripped:
                payload.append(stripped)
        try:
            body = base64.b64decode("".join(payload), validate=True)
        except Exception as exc:
            raise PemError(f"base64 invalide dans le bloc {match.group('tag')}") from exc
        out.append((match.group("tag"), headers, body))
    return out


def _looks_like_base64(line: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", line))


def decode_one(text: str, tag: str) -> tuple[dict[str, str], bytes]:
    """Renvoie l'unique bloc portant ce tag."""
    blocks = [b for b in decode_all(text) if b[0] == tag]
    if not blocks:
        raise PemError(f"aucun bloc '{tag}' dans le fichier")
    if len(blocks) > 1:
        raise PemError(f"plusieurs blocs '{tag}' dans le fichier")
    return blocks[0][1], blocks[0][2]


def has_block(text: str, tag: str) -> bool:
    return any(b[0] == tag for b in decode_all(text))
