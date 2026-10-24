"""Autorite d'enregistrement (Register Authority).

Le RA possede sa propre paire de cles et fixe tau0, le parametre de
domaine public du schema.  Il signe des certificats qui lient l'identite
d'une personne a ses deux cles publiques SN.

Deux operations publiques :
  - ra_sign   : le RA emet un certificat pour un sujet
  - ra_verify : n'importe qui controle un certificat avec la cle
                publique du RA, et sait donc a qui appartient pk_sd
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import pem
from .primitives import KEY_LEN, get_suite

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RA_DIR = PROJECT_ROOT / ".ra"
REGISTER_DIR = PROJECT_ROOT / "register-key"

_RA_FILE = "ra.json"
_ISSUED = "issued"

CERT_TAG = "SN CERTIFICATE"
KEY_TAG = "SN ENCRYPTED PRIVATE KEY"

DEFAULT_VALIDITY_DAYS = 730


def _canonical(obj: dict) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Subject:
    """L'identite declaree du signataire."""

    name: str
    email: str
    role: str
    organization: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Subject":
        return cls(d["name"], d["email"], d["role"], d["organization"])

    def __str__(self) -> str:
        return f"{self.name} <{self.email}>, {self.role}, {self.organization}"


@dataclass(frozen=True)
class Certificate:
    serial: str
    subject: Subject
    suite: str
    pk_sd: bytes
    pk_rcv: bytes
    tau0: bytes
    not_before: str
    not_after: str
    issuer: str
    issuer_suite: str
    issuer_key: bytes
    signature: bytes = b""

    # --- contenu signe ---

    def payload(self) -> bytes:
        """Les champs couverts par la signature du RA."""
        return _canonical(
            {
                "serial": self.serial,
                "subject": self.subject.to_dict(),
                "suite": self.suite,
                "pk_sd": self.pk_sd.hex(),
                "pk_rcv": self.pk_rcv.hex(),
                "tau0": self.tau0.hex(),
                "not_before": self.not_before,
                "not_after": self.not_after,
                "issuer": self.issuer,
                "issuer_suite": self.issuer_suite,
                "issuer_key": self.issuer_key.hex(),
            }
        )

    def to_dict(self) -> dict:
        d = json.loads(self.payload())
        d["signature"] = self.signature.hex()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Certificate":
        return cls(
            serial=d["serial"],
            subject=Subject.from_dict(d["subject"]),
            suite=d["suite"],
            pk_sd=bytes.fromhex(d["pk_sd"]),
            pk_rcv=bytes.fromhex(d["pk_rcv"]),
            tau0=bytes.fromhex(d["tau0"]),
            not_before=d["not_before"],
            not_after=d["not_after"],
            issuer=d["issuer"],
            issuer_suite=d["issuer_suite"],
            issuer_key=bytes.fromhex(d["issuer_key"]),
            signature=bytes.fromhex(d["signature"]),
        )

    def fingerprint(self) -> str:
        return hashlib.sha256(self.payload()).hexdigest()[:16]

    def issuer_fingerprint(self) -> str:
        return hashlib.sha256(self.issuer_key).hexdigest()[:16]

    def is_current(self, at: datetime | None = None) -> bool:
        moment = at or _now()
        return (
            datetime.fromisoformat(self.not_before)
            <= moment
            <= datetime.fromisoformat(self.not_after)
        )

    # --- PEM ---

    def headers(self) -> dict[str, str]:
        """En-tetes lisibles.  Purement informatifs : ils ne sont pas
        signes, et from_pem signale toute divergence avec le corps."""
        return {
            "Name": self.subject.name,
            "Email": self.subject.email,
            "Role": self.subject.role,
            "Organization": self.subject.organization,
            "Serial": self.serial,
            "Suite": self.suite,
            "Issuer": self.issuer,
            "Issuer-Fingerprint": self.issuer_fingerprint(),
            "Not-Before": self.not_before,
            "Not-After": self.not_after,
            "Fingerprint": self.fingerprint(),
        }

    def to_pem(self) -> str:
        body = json.dumps(self.to_dict(), separators=(",", ":")).encode("utf-8")
        return pem.encode(CERT_TAG, self.headers(), body)

    @classmethod
    def from_pem(cls, text: str) -> tuple["Certificate", list[str]]:
        """Lit un certificat.  Renvoie aussi la liste des en-tetes qui ne
        correspondent pas au corps signe."""
        headers, body = pem.decode_one(text, CERT_TAG)
        try:
            cert = cls.from_dict(json.loads(body.decode("utf-8")))
        except (ValueError, KeyError) as exc:
            raise pem.PemError(f"corps de certificat illisible : {exc}") from exc
        truth = cert.headers()
        mismatched = [
            k for k, v in headers.items() if k in truth and truth[k] != v
        ]
        return cert, mismatched


@dataclass(frozen=True)
class RA:
    name: str
    suite: str
    sk: bytes
    pk: bytes
    tau0: bytes
    created: str

    def fingerprint(self) -> str:
        return hashlib.sha256(self.pk).hexdigest()[:16]


@dataclass
class VerifyResult:
    """Ce que repond RA-verify."""

    subject: Subject
    signature_ok: bool
    period_ok: bool
    issuer_matches: bool | None = None  # None = RA local introuvable
    headers_ok: bool = True
    problems: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return (
            self.signature_ok
            and self.period_ok
            and self.issuer_matches is not False
            and self.headers_ok
        )


# --- gestion du RA ----------------------------------------------------------


def ra_path(directory: Path | None = None) -> Path:
    return (directory or RA_DIR) / _RA_FILE


def exists(directory: Path | None = None) -> bool:
    return ra_path(directory).exists()


def ra_init(
    name: str = "SN Register Authority",
    suite: str = "classical",
    directory: Path | None = None,
) -> RA:
    """Cree le RA.  Refuse d'ecraser : cela invaliderait tous les
    certificats deja emis."""
    target = ra_path(directory)
    if target.exists():
        raise FileExistsError(
            f"un RA existe deja dans {target.parent} ; "
            "le remplacer invaliderait tous les certificats emis"
        )
    s = get_suite(suite)
    sk, pk = s.sig.generate()
    ra = RA(
        name=name, suite=suite, sk=sk, pk=pk,
        tau0=os.urandom(KEY_LEN),
        created=_now().isoformat(timespec="seconds"),
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    (target.parent / _ISSUED).mkdir(exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(
            {
                "version": 1, "name": ra.name, "suite": ra.suite,
                "sk": ra.sk.hex(), "pk": ra.pk.hex(),
                "tau0": ra.tau0.hex(), "created": ra.created,
            },
            fh, indent=2,
        )
    return ra


def ra_load(directory: Path | None = None) -> RA:
    target = ra_path(directory)
    if not target.exists():
        raise FileNotFoundError(
            f"aucun RA dans {target.parent} ; lance d'abord 'sn ra init'"
        )
    d = json.loads(target.read_text())
    return RA(
        name=d["name"], suite=d["suite"],
        sk=bytes.fromhex(d["sk"]), pk=bytes.fromhex(d["pk"]),
        tau0=bytes.fromhex(d["tau0"]), created=d["created"],
    )


# --- RA-sign / RA-verify ----------------------------------------------------


def ra_sign(
    ra: RA,
    subject: Subject,
    suite: str,
    pk_sd: bytes,
    pk_rcv: bytes,
    days: int = DEFAULT_VALIDITY_DAYS,
    directory: Path | None = None,
) -> Certificate:
    """RA-sign : le RA emet et signe un certificat pour ce sujet."""
    user = get_suite(suite)
    user.sig.validate_pk(pk_sd)
    user.kem.validate_pk(pk_rcv)

    start = _now()
    unsigned = Certificate(
        serial=os.urandom(8).hex(),
        subject=subject,
        suite=suite,
        pk_sd=pk_sd,
        pk_rcv=pk_rcv,
        tau0=ra.tau0,
        not_before=start.isoformat(timespec="seconds"),
        not_after=(start + timedelta(days=days)).isoformat(timespec="seconds"),
        issuer=ra.name,
        issuer_suite=ra.suite,
        issuer_key=ra.pk,
    )
    signature = get_suite(ra.suite).sig.sign(ra.sk, unsigned.payload())
    cert = Certificate(**{**unsigned.__dict__, "signature": signature})

    log = (directory or RA_DIR) / _ISSUED / f"{cert.serial}.pem"
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(cert.to_pem())
    return cert


def ra_verify(
    cert: Certificate,
    ra: RA | None = None,
    mismatched_headers: list[str] | None = None,
    at: datetime | None = None,
) -> VerifyResult:
    """RA-verify : controle un certificat avec la cle publique du RA.

    C'est ce qui permet de dire a qui appartient pk_sd.  Ne demande aucun
    secret : la cle publique du RA suffit.
    """
    problems: list[str] = []

    sig_alg = get_suite(cert.issuer_suite).sig
    try:
        sig_alg.validate_pk(cert.issuer_key)
        signature_ok = sig_alg.verify(cert.issuer_key, cert.payload(), cert.signature)
    except ValueError:
        signature_ok = False
    if not signature_ok:
        problems.append("la signature du RA est invalide")

    period_ok = cert.is_current(at)
    if not period_ok:
        moment = at or _now()
        when = "pas encore valide" if moment < datetime.fromisoformat(
            cert.not_before
        ) else "expire"
        problems.append(f"certificat {when}")

    issuer_matches = None
    if ra is not None:
        issuer_matches = cert.issuer_key == ra.pk
        if not issuer_matches:
            problems.append("emis par un autre RA que le RA local")

    headers_ok = not mismatched_headers
    if mismatched_headers:
        problems.append(
            "en-tetes lisibles falsifies : " + ", ".join(sorted(mismatched_headers))
        )

    return VerifyResult(
        subject=cert.subject,
        signature_ok=signature_ok,
        period_ok=period_ok,
        issuer_matches=issuer_matches,
        headers_ok=headers_ok,
        problems=problems,
    )


def ra_verify_file(
    path: Path, ra: RA | None = None, at: datetime | None = None
) -> tuple[Certificate, VerifyResult]:
    """RA-verify sur un fichier .pem."""
    cert, mismatched = Certificate.from_pem(Path(path).read_text())
    return cert, ra_verify(cert, ra, mismatched, at)
