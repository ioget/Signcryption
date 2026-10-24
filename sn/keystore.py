"""Comptes utilisateur : un fichier .pem par compte dans register-key/.

Chaque fichier contient deux blocs PEM :
  - SN CERTIFICATE          : public, avec les donnees personnelles
                              lisibles en en-tete ;
  - SN ENCRYPTED PRIVATE KEY: sk_sd et sk_rcv, chiffres par le mot de
                              passe de l'utilisateur.

Signer exige donc le mot de passe.  Verifier n'en a jamais besoin.
Plusieurs comptes coexistent : un fichier chacun.
"""

from __future__ import annotations

import json
import os
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import pem, vault
from .codec import pack, unpack
from .ra import CERT_TAG, KEY_TAG, REGISTER_DIR, RA, Certificate, Subject, ra_sign
from .primitives import get_suite
from .scheme import DomainParams, gen_rcv, gen_sd


def slugify(name: str) -> str:
    """Nom de fichier sur : accents retires, espaces en tirets."""
    plain = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", plain).strip("-").lower()
    return slug or "compte"


def register_dir(directory: Path | None = None) -> Path:
    return directory or Path(os.environ.get("SN_REGISTER", REGISTER_DIR))


@dataclass(frozen=True)
class Account:
    """Un compte : certificat public + coffre chiffre."""

    cert: Certificate
    _vault: dict
    path: Path
    header_problems: tuple[str, ...] = ()

    @property
    def subject(self) -> Subject:
        return self.cert.subject

    @property
    def pk_sd(self) -> bytes:
        return self.cert.pk_sd

    @property
    def pk_rcv(self) -> bytes:
        return self.cert.pk_rcv

    @property
    def dp(self) -> DomainParams:
        # tau0 vient du RA, via le certificat.
        return DomainParams(suite=get_suite(self.cert.suite), tau0=self.cert.tau0)

    def unlock(self, password: str) -> "Unlocked":
        raw = vault.unseal(password, self._vault, aad=self.cert.serial.encode())
        # Deux champs pour un compte sans donnees privees, trois sinon :
        # les comptes crees avant cette option restent lisibles.
        fields = unpack(raw)
        if len(fields) == 2:
            sk_sd, sk_rcv, private = *fields, {}
        elif len(fields) == 3:
            sk_sd, sk_rcv, blob = fields
            private = json.loads(blob.decode("utf-8"))
        else:
            raise ValueError("contenu de coffre inattendu")
        return Unlocked(
            account=self, sk_sd=sk_sd, sk_rcv=sk_rcv, private=private
        )


@dataclass(frozen=True)
class Unlocked:
    account: Account
    sk_sd: bytes
    sk_rcv: bytes
    private: dict = field(default_factory=dict)

    @property
    def dp(self) -> DomainParams:
        return self.account.dp

    @property
    def cert(self) -> Certificate:
        return self.account.cert


def create(
    subject: Subject,
    password: str,
    ra: RA,
    suite: str = "classical",
    directory: Path | None = None,
    ra_directory: Path | None = None,
    private: dict[str, str] | None = None,
) -> Account:
    """Genere les cles, fait signer le certificat par le RA, ecrit le .pem.

    Chaque appel cree un nouveau fichier : plusieurs comptes coexistent.

    `private` contient des donnees personnelles qui vont dans le coffre
    plutot que dans le certificat : elles ne sont lisibles qu'avec le mot
    de passe, et le RA ne les signe pas.
    """
    s = get_suite(suite)
    dp = DomainParams(suite=s, tau0=ra.tau0)
    sk_sd, pk_sd = gen_sd(dp)
    sk_rcv, pk_rcv = gen_rcv(dp)

    cert = ra_sign(ra, subject, suite, pk_sd, pk_rcv, directory=ra_directory)
    # Le numero de serie est authentifie avec le coffre : le coffre d'un
    # compte ne peut pas etre recolle sur le certificat d'un autre.
    secret = [sk_sd, sk_rcv]
    if private:
        secret.append(json.dumps(private, ensure_ascii=False).encode("utf-8"))
    sealed = vault.seal(password, pack(*secret), aad=cert.serial.encode())

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    target = register_dir(directory) / f"{slugify(subject.name)}-{stamp}.pem"
    target.parent.mkdir(parents=True, exist_ok=True)

    text = cert.to_pem() + pem.encode(
        KEY_TAG,
        {"Serial": cert.serial, "KDF": "scrypt", "Cipher": "aes-256-gcm"},
        json.dumps(sealed, separators=(",", ":")).encode("utf-8"),
    )
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return Account(cert=cert, _vault=sealed, path=target)


def load(path: Path) -> Account:
    """Charge un compte depuis son .pem.  Ne demande pas de mot de passe."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"aucun compte a {path}")
    text = path.read_text()
    cert, mismatched = Certificate.from_pem(text)
    if not pem.has_block(text, KEY_TAG):
        raise ValueError(
            f"{path} ne contient pas de bloc '{KEY_TAG}' ; "
            "c'est un certificat seul, pas un compte"
        )
    _, body = pem.decode_one(text, KEY_TAG)
    return Account(
        cert=cert,
        _vault=json.loads(body.decode("utf-8")),
        path=path,
        header_problems=tuple(mismatched),
    )


def discover(directory: Path | None = None) -> list[Path]:
    """Tous les comptes du registre, du plus recent au plus ancien."""
    folder = register_dir(directory)
    if not folder.exists():
        return []
    return sorted(folder.glob("*.pem"), key=lambda p: p.name, reverse=True)


def resolve(
    selector: str | None = None, directory: Path | None = None
) -> Account:
    """Choisit le compte a utiliser.

    - un chemin de fichier : ce compte ;
    - un nom ou un email : le compte qui correspond ;
    - rien : l'unique compte du registre, sinon on demande de choisir.
    """
    if selector and Path(selector).suffix == ".pem" and Path(selector).exists():
        return load(Path(selector))

    found = discover(directory)
    if not found:
        raise FileNotFoundError(
            f"aucun compte dans {register_dir(directory)} ; "
            "lance d'abord 'sn init'"
        )

    accounts = [load(p) for p in found]
    if selector:
        needle = selector.lower()
        matches = [
            a for a in accounts
            if needle in (a.subject.name.lower(), a.subject.email.lower())
            or a.cert.serial.startswith(needle)
            or needle in a.path.name.lower()
        ]
        if not matches:
            raise FileNotFoundError(f"aucun compte ne correspond a {selector!r}")
        if len(matches) > 1:
            listing = ", ".join(a.path.name for a in matches)
            raise ValueError(f"{selector!r} correspond a plusieurs comptes : {listing}")
        return matches[0]

    if len(accounts) > 1:
        listing = "\n".join(
            f"    {a.path.name}  ({a.subject.name} <{a.subject.email}>)"
            for a in accounts
        )
        raise ValueError(
            f"{len(accounts)} comptes disponibles ; precise lequel avec "
            f"--cert <fichier.pem> :\n{listing}"
        )
    return accounts[0]
