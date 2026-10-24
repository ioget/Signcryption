"""Banniere ASCII et animations du mode Cryptographe.

Tout est inhibe des que la sortie n'est pas un terminal -- script, pipe,
tests -- pour que le texte utile reste identique et exploitable.
SN_NO_BANNER=1 coupe aussi l'affichage en terminal.
"""

from __future__ import annotations

import os
import random
import sys
import time

ACTIF = sys.stdout.isatty() and not os.environ.get("SN_NO_BANNER")

# Cadences : assez vives pour ne pas faire attendre.
_PAS = 0.045
_CAR = 0.004

_SPINNERS = [
    "|/-\\",
    "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏",
    "▁▂▃▄▅▆▇█▇▆▅▄▃▂",
    "◐◓◑◒",
    "⣾⣽⣻⢿⡿⣟⣯⣷",
    "←↖↑↗→↘↓↙",
]

_RA_ART = r"""
   ██████╗  █████╗
   ██╔══██╗██╔══██╗     R E G I S T E R
   ██████╔╝███████║     A U T H O R I T Y
   ██╔══██╗██╔══██║
   ██║  ██║██║  ██║
   ╚═╝  ╚═╝╚═╝  ╚═╝
"""

_SN_ART = r"""
   ███████╗███╗   ██╗
   ██╔════╝████╗  ██║     S I G N C R Y P T I O N
   ███████╗██╔██╗ ██║
   ╚════██║██║╚██╗██║     insider secure · NINR
   ███████║██║ ╚████║
   ╚══════╝╚═╝  ╚═══╝
"""

# Affichee sous chaque banniere, quelle que soit la commande.
_SIGNATURE = "Signcryption, Author <Togde & Sarr>"

_EPIGRAPHES_RA = [
    "Une autorite ne vaut que par la discretion de sa cle.",
    "Celui qui signe les certificats tient la racine de la confiance.",
    "tau0 fixe le domaine : tous vos certificats en dependront.",
    "Une seule racine, et pour longtemps.",
    "La confiance ne se decrete pas, elle s'enracine.",
]

_EPIGRAPHES_COMPTE = [
    "Votre cle privee ne quittera jamais ce fichier en clair.",
    "Un mot de passe perdu est un compte perdu : il n'y a pas de double.",
    "Signer engage ; chiffrer protege ; prouver tranche.",
    "L'identite publique se montre, la cle privee se tait.",
    "Deux paires de cles : l'une signe, l'autre recoit.",
]

_ETAPES_RA = [
    ("Collecte de l'entropie du systeme", "os.urandom"),
    ("Generation de la paire de cles de l'autorite", None),
    ("Tirage du parametre de domaine tau0", "32 octets"),
    ("Scellement du trousseau de l'autorite", "0600"),
]

_ETAPES_COMPTE = [
    ("Generation de la paire de signature", None),
    ("Generation de la paire d'encapsulation", None),
    ("Derivation de la cle de coffre (scrypt)", "N=2^15"),
    ("Chiffrement des cles privees (AES-256-GCM)", None),
    ("Signature du certificat par le RA", None),
]

# Les etapes nommees d'apres le schema du papier : chaque ligne
# correspond a une operation reelle de Sc, Usc, N ou PV.
_ETAPES_SIGNER = [
    ("Ouverture du coffre", "scrypt"),
    ("Encapsulation vers le destinataire", "c1"),
    ("Derivation des quatre cles de session", "tau1..tau2'"),
    ("Chiffrement du document", "c2"),
    ("Calcul de l'empreinte signee", "m-hat"),
    ("Signature", "sigma"),
    ("Scellement du tag", "t = Prf(tau1', sigma)"),
]
_ETAPES_CHIFFRER = [
    ("Controle du certificat du destinataire", None),
    ("Ouverture du coffre", "scrypt"),
    ("Encapsulation vers le destinataire", "c1"),
    ("Chiffrement du document", "ChaCha20"),
    ("Signature de l'empreinte", "sigma"),
]
_ETAPES_DECHIFFRER = [
    ("Ouverture du coffre", "scrypt"),
    ("Decapsulation", "Dcp(sk_rcv, c1)"),
    ("Reconstitution de l'empreinte", "m-hat"),
    ("Verification de la signature", None),
    ("Dechiffrement du document", None),
]
_ETAPES_VERIFIER = [
    ("Lecture de la preuve", None),
    ("Reconstitution de l'empreinte", "m-hat"),
    ("Verification de la signature", None),
    ("Controle du tag", None),
]

_JEUX = {
    "ra": _ETAPES_RA,
    "compte": _ETAPES_COMPTE,
    "signer": _ETAPES_SIGNER,
    "chiffrer": _ETAPES_CHIFFRER,
    "dechiffrer": _ETAPES_DECHIFFRER,
    "verifier": _ETAPES_VERIFIER,
}

_TITRES = {
    "signer": "signature",
    "chiffrer": "signcryption",
    "dechiffrer": "ouverture",
    "verifier": "verification",
}


def _c(texte: str, code: str) -> str:
    return f"\033[{code}m{texte}\033[0m" if ACTIF else texte


def _ecrire_lentement(texte: str, code: str = "36") -> None:
    """La couleur est ouverte une fois, pas a chaque caractere."""
    sys.stdout.write(f"\033[{code}m")
    for caractere in texte:
        sys.stdout.write(caractere)
        sys.stdout.flush()
        time.sleep(_CAR)
    sys.stdout.write("\033[0m\n")


def banniere(genre: str) -> None:
    """genre : 'ra' ou 'compte'."""
    if not ACTIF:
        return
    art = _RA_ART if genre == "ra" else _SN_ART
    couleur = "35" if genre == "ra" else "36"
    for ligne in art.strip("\n").splitlines():
        print(_c(ligne, couleur))
        time.sleep(_PAS / 2)
    print()
    print(_c(f"   {_SIGNATURE}", "1"))
    epigraphe = random.choice(
        _EPIGRAPHES_RA if genre == "ra" else _EPIGRAPHES_COMPTE
    )
    _ecrire_lentement(f"   « {epigraphe} »", "2")
    print()


def entete(genre: str) -> None:
    """Un bandeau d'une ligne, pour les commandes courantes."""
    if not ACTIF:
        return
    titre = _TITRES.get(genre, genre)
    print(_c(f"  ┌─ {titre} ─────────────────────────────────────", "2"))


def etapes(genre: str) -> None:
    """Deroule les etapes du travail, avec un spinner tire au hasard."""
    if not ACTIF:
        return
    trames = random.choice(_SPINNERS)
    liste = _JEUX.get(genre, ())
    court = genre not in ("ra", "compte")
    for libelle, detail in liste:
        for i in range(random.randint(2, 4) if court else random.randint(5, 9)):
            sys.stdout.write(
                f"\r  {_c(trames[i % len(trames)], '36')} {libelle}…   "
            )
            sys.stdout.flush()
            time.sleep(_PAS)
        suffixe = _c(f"  [{detail}]", "2") if detail else ""
        sys.stdout.write(f"\r  {_c('✓', '32')} {libelle}{suffixe}\033[K\n")
        sys.stdout.flush()
    print()


def conclusion(genre: str) -> None:
    if not ACTIF:
        return
    trait = "─" * 58
    print(_c(f"  {trait}", "2"))
    message = (
        "Racine de confiance etablie."
        if genre == "ra"
        else "Compte enregistre et certifie."
    )
    _ecrire_lentement(f"  {message}", "32")
    print()
