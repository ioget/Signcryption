"""The verification record carried by the QR code (or sidecar file).

What travels is everything PV needs *except* c2.  c2 is the size of the
whole document, so instead the verifier recomputes it from the original
file and tau1, which works because the symmetric scheme is deterministic
and length preserving.  Soundness is unchanged: for m' != m both
c2' != c2 and tau3' != tau3, so m-hat differs and the signature fails to
verify -- the argument of Theorem 3.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .codec import pack, unpack
from .primitives import SUITES_BY_ID
from .scheme import Ciphertext, DomainParams, Keys, pv, pv_checks

VERSION = 3


@dataclass(frozen=True)
class Metadata:
    """Bound to the document by being part of the signcrypted message."""

    timestamp: str  # ISO-8601 UTC
    filename: str
    signer: str
    title: str = ""
    reference: str = ""  # numero d'ordre, facultatif

    def _fields(self) -> tuple[bytes, ...]:
        return (
            self.timestamp.encode(),
            self.filename.encode(),
            self.signer.encode(),
            self.title.encode(),
            self.reference.encode(),
        )

    def to_bytes(self) -> bytes:
        return pack(*self._fields())

    @classmethod
    def from_bytes(cls, b: bytes) -> "Metadata":
        ts, fn, sg, ti, rf = unpack(b, count=5)
        return cls(
            ts.decode(), fn.decode(), sg.decode(), ti.decode(), rf.decode()
        )

    @classmethod
    def now(
        cls, filename: str, signer: str, title: str = "", reference: str = ""
    ) -> "Metadata":
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            filename=filename,
            signer=signer,
            title=title,
            reference=reference,
        )


def build_message(meta: Metadata, document: bytes) -> bytes:
    """m = (timestamp, filename, signer, title, reference, document).

    Metadata is simply part of the plaintext, so the scheme is untouched:
    whatever is in m is what the signature covers.  Changing the title or
    the order number therefore breaks the signature, exactly like
    changing a byte of the document.
    """
    return pack(*meta._fields(), document)


def split_message(m: bytes) -> tuple[Metadata, bytes]:
    """Inverse de build_message : separe les metadonnees du document."""
    fields = unpack(m)
    if len(fields) != 6:
        raise ValueError(f"message malforme : {len(fields)} champs au lieu de 6")
    ts, fn, sg, ti, rf, document = fields
    return (
        Metadata(ts.decode(), fn.decode(), sg.decode(), ti.decode(), rf.decode()),
        document,
    )


@dataclass(frozen=True)
class Evidence:
    """Everything a verifier needs, alongside the original document."""

    dp: DomainParams
    meta: Metadata
    pk_sd: bytes
    pk_rcv: bytes
    c1: bytes
    sigma: bytes
    t: bytes
    nr: Keys
    prefix_len: int = 0
    """Octets du fichier reellement signes; 0 = le fichier entier.

    Pour un PDF signe de maniere visible, le QR est ajoute apres coup en
    mise a jour incrementale, et seuls les prefix_len premiers octets
    sont couverts.  Ce champ n'est pas signe, mais il n'a pas besoin de
    l'etre : le fausser donne un autre prefixe, donc un autre document,
    donc une signature invalide.
    """

    def to_bytes(self) -> bytes:
        return pack(
            bytes([VERSION]),
            bytes([self.dp.suite.id]),
            self.dp.tau0,
            self.pk_sd,
            self.pk_rcv,
            self.c1,
            self.sigma,
            self.t,
            self.nr.to_bytes(),
            self.meta.to_bytes(),
            self.prefix_len.to_bytes(8, "big"),
        )

    @classmethod
    def from_bytes(cls, blob: bytes) -> "Evidence":
        # La version est lue avant tout le reste : une preuve d'une
        # version precedente doit donner un message clair, pas une
        # erreur sur le nombre de champs.
        fields = unpack(blob)
        if not fields or len(fields[0]) != 1:
            raise ValueError("preuve illisible : en-tete de version absent")
        if fields[0][0] != VERSION:
            raise ValueError(
                f"preuve en version {fields[0][0]}, cet outil lit la version "
                f"{VERSION} ; refais la signature pour regenerer le QR code"
            )
        if len(fields) != 11:
            raise ValueError(
                f"preuve malformee : {len(fields)} champs au lieu de 11"
            )
        (ver, sid, tau0, pk_sd, pk_rcv, c1, sigma, t, nr, meta,
         prefix) = fields
        if len(sid) != 1 or sid[0] not in SUITES_BY_ID:
            raise ValueError("unknown cipher suite in evidence")
        return cls(
            dp=DomainParams(suite=SUITES_BY_ID[sid[0]], tau0=tau0),
            meta=Metadata.from_bytes(meta),
            pk_sd=pk_sd,
            pk_rcv=pk_rcv,
            c1=c1,
            sigma=sigma,
            t=t,
            nr=Keys.from_bytes(nr),
            prefix_len=int.from_bytes(prefix, "big"),
        )

    def _rebuild(self, document: bytes) -> tuple[bytes, Ciphertext]:
        m = build_message(self.meta, document)
        # c2 travels nowhere; rebuild it from the document and tau1.
        c2 = self.dp.suite.sym.encrypt(self.nr.t1, m)
        return m, Ciphertext(t=self.t, sigma=self.sigma, c1=self.c1, c2=c2)

    def verify(self, document: bytes) -> bool:
        """Run PV against a candidate document."""
        m, C = self._rebuild(document)
        return pv(self.dp, C, m, self.nr, self.pk_sd, self.pk_rcv)

    def checks(self, document: bytes) -> dict[str, bool]:
        """Per-check results, for reporting which one failed."""
        m, C = self._rebuild(document)
        return pv_checks(self.dp, C, m, self.nr, self.pk_sd, self.pk_rcv)
