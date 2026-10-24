"""Message signcrypte complet, pour un destinataire precis.

Contrairement au mode QR -- ou c2 est recalcule a la verification et le
document reste en clair -- ici c2 est reellement transporte : le fichier
.snc est opaque, et seul le detenteur de sk_rcv peut l'ouvrir.

C'est le scenario du papier, avec ses trois proprietes a la fois :
confidentialite, authenticite, et non-repudiation non interactive.
"""

from __future__ import annotations

from dataclasses import dataclass

from .codec import pack, unpack
from .evidence import Metadata, build_message, split_message
from .primitives import SUITES_BY_ID
from .scheme import Ciphertext, DomainParams, Keys, n as nr_generate, pv, usc

VERSION = 1


@dataclass(frozen=True)
class Sealed:
    """Le contenu d'un fichier .snc."""

    dp: DomainParams
    meta: Metadata
    pk_sd: bytes
    pk_rcv: bytes
    C: Ciphertext

    def to_bytes(self) -> bytes:
        return pack(
            bytes([VERSION]),
            bytes([self.dp.suite.id]),
            self.dp.tau0,
            self.pk_sd,
            self.pk_rcv,
            self.C.t,
            self.C.sigma,
            self.C.c1,
            self.C.c2,
            self.meta.to_bytes(),
        )

    @classmethod
    def from_bytes(cls, blob: bytes) -> "Sealed":
        fields = unpack(blob)
        if not fields or len(fields[0]) != 1:
            raise ValueError("fichier scelle illisible : en-tete absent")
        if fields[0][0] != VERSION:
            raise ValueError(
                f"fichier en version {fields[0][0]}, cet outil lit la version "
                f"{VERSION}"
            )
        if len(fields) != 10:
            raise ValueError(f"fichier malforme : {len(fields)} champs au lieu de 10")
        _, sid, tau0, pk_sd, pk_rcv, t, sigma, c1, c2, meta = fields
        if len(sid) != 1 or sid[0] not in SUITES_BY_ID:
            raise ValueError("suite cryptographique inconnue")
        return cls(
            dp=DomainParams(suite=SUITES_BY_ID[sid[0]], tau0=tau0),
            meta=Metadata.from_bytes(meta),
            pk_sd=pk_sd,
            pk_rcv=pk_rcv,
            C=Ciphertext(t=t, sigma=sigma, c1=c1, c2=c2),
        )

    # --- operations du destinataire ---

    def open(self, sk_rcv: bytes) -> bytes | None:
        """Usc : rend le document, ou None si le controle echoue."""
        m = usc(self.dp, sk_rcv, self.pk_sd, self.C)
        if m is None:
            return None
        return self._document(m)

    def evidence(self, sk_rcv: bytes) -> Keys | None:
        """N : la preuve de non-repudiation, remettable a un arbitre."""
        return nr_generate(self.dp, sk_rcv, self.pk_sd, self.C)

    def _document(self, m: bytes) -> bytes:
        """Retire les metadonnees du message pour rendre le fichier seul."""
        return split_message(m)[1]

    # --- arbitrage, sans aucun secret ---

    def check(self, document: bytes, nr: Keys) -> bool:
        """PV : prouve publiquement que pk_sd a bien envoye ce document."""
        m = build_message(self.meta, document)
        return pv(self.dp, self.C, m, nr, self.pk_sd, self.pk_rcv)
