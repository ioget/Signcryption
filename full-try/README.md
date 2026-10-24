# full-try — signcryption complete sur l'attestation de rang

Chiffrement + signature + dechiffrement + arbitrage, sur un vrai PDF.

## Les commandes

```bash
R=register-key/rosly-mamakem-20261009T211003.pem
F=register-key/fatou-ndiaye-20261009T211004.pem

# 0. certificats publics
./sn-cli account export --cert $F -o full-try/fatou-public.pem
./sn-cli account export --cert $R -o full-try/rosly-public.pem

# 1. Rosly chiffre et signe pour Fatou        (mot de passe : Mot2Passe!rosly)
./sn-cli encrypt full-try/letter_attestation_rang.pdf \
    --to full-try/fatou-public.pem --cert $R \
    --title "Demande attestation de rang" --ref "No 007/26" \
    -o full-try/attestation-rang.snc

# 2. copie du fichier scelle
cp full-try/attestation-rang.snc full-try/attestation-rang-copie.snc

# 3. Fatou dechiffre et garde la preuve       (mot de passe : Autre!Passe99)
./sn-cli decrypt full-try/attestation-rang.snc --cert $F \
    -o full-try/attestation-rang-dechiffre.pdf --proof full-try/preuve.nr

# 4. un arbitre etablit l'origine              (aucun mot de passe)
./sn-cli arbitrate full-try/attestation-rang.snc \
    --document full-try/attestation-rang-dechiffre.pdf \
    --proof full-try/preuve.nr --cert full-try/rosly-public.pem
```

## Les fichiers

| Fichier | Quoi | Taille |
|---|---|---|
| `letter_attestation_rang.pdf` | le PDF de depart | 75 129 o |
| `attestation-rang.snc` | chiffre + signe pour Fatou | 75 641 o |
| `attestation-rang-copie.snc` | copie, identique | 75 641 o |
| `attestation-rang-dechiffre.pdf` | restitue par Fatou | 75 129 o |
| `depuis-copie.pdf` | restitue depuis la copie | 75 129 o |
| `preuve.nr` | preuve de non-repudiation | 192 o |
| `rosly-public.pem` / `fatou-public.pem` | certificats publics | — |

## Resultats

| Verification | Resultat |
|---|---|
| le `.snc` est-il un PDF ? | non — `file` dit `data`, pypdf refuse |
| texte lisible dans le `.snc` ? | 0 occurrence de "Gnintezemo" |
| PDF dechiffre vs original | **identique octet par octet** (`cmp`) |
| le PDF dechiffre s'ouvre ? | oui — 1 page, texte extrait |
| la copie du `.snc` fonctionne ? | oui, meme PDF restitue |
| arbitrage | `✓ ORIGINE ETABLIE` · `cle liee ✓` |

Surcout du chiffrement : **512 octets**, soit +0,7 %.
