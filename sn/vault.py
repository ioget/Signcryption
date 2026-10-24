"""Chiffrement des cles privees par mot de passe.

scrypt pour deriver une cle depuis le mot de passe, puis AES-256-GCM.
GCM est authentifie : un mauvais mot de passe echoue proprement au lieu
de rendre des octets faux.
"""

from __future__ import annotations

import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ~100 ms et 32 Mio par essai : assez lent pour gener une attaque par
# dictionnaire hors ligne, assez rapide pour ne pas gener l'utilisateur.
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12

MIN_PASSWORD_LEN = 8


class BadPassword(ValueError):
    """Mot de passe incorrect, ou donnees alterees."""


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def seal(password: str, plaintext: bytes, aad: bytes = b"") -> dict[str, Any]:
    """Chiffre `plaintext`.  `aad` est authentifie mais pas chiffre."""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "kdf": {
            "algo": "scrypt",
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "salt": salt.hex(),
        },
        "cipher": "aes-256-gcm",
        "nonce": nonce.hex(),
        "ciphertext": ct.hex(),
    }


def unseal(password: str, blob: dict[str, Any], aad: bytes = b"") -> bytes:
    """Dechiffre.  Leve BadPassword si le mot de passe est faux."""
    kdf = blob["kdf"]
    if kdf.get("algo") != "scrypt" or blob.get("cipher") != "aes-256-gcm":
        raise ValueError("format de coffre non reconnu")
    key = _derive(
        password, bytes.fromhex(kdf["salt"]), kdf["n"], kdf["r"], kdf["p"]
    )
    try:
        return AESGCM(key).decrypt(
            bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["ciphertext"]), aad
        )
    except InvalidTag:
        raise BadPassword("mot de passe incorrect") from None


def check_strength(password: str) -> str | None:
    """Renvoie un avertissement, ou None si le mot de passe convient."""
    if len(password) < MIN_PASSWORD_LEN:
        return f"trop court (minimum {MIN_PASSWORD_LEN} caracteres)"
    if password.isdigit() or password.isalpha():
        return "faible : melange lettres, chiffres et symboles"
    return None
