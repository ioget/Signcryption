# Guide d'utilisation `sn-cli`

Signer des documents et les verifier par QR code, avec le schema de
signcryption SN.

> Toutes les commandes se lancent depuis le dossier du projet.
> Remplace `./sn-cli` par le chemin complet si tu l'appelles d'ailleurs.

---

## En deux minutes

Les trois commandes que tu utiliseras tous les jours :

```bash
# signer un PDF le QR est incruste dedans
./sn-cli sign attestation.pdf --pdf --cert register-key/mon-compte.pem

# verifier un seul fichier suffit
./sn-cli verify attestation-signe.pdf --pdf

# verifier ET prouver qui a signe
./sn-cli verify attestation-signe.pdf --pdf --cert certificat-public.pem
```

Et quand le document doit rester secret (section 4) :

```bash
./sn-cli encrypt rapport.txt --to fatou-public.pem --cert register-key/mon-compte.pem
./sn-cli decrypt rapport.txt.snc --cert register-key/mon-compte.pem
```

---

## 1. Premiere installation

A faire une seule fois.

### Installer les dependances

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### Creer l'autorite d'enregistrement (RA)

Le RA signe les certificats. **Une seule fois, jamais deux** : le
recreer invaliderait tous les certificats deja emis.

```bash
./sn-cli ra init --name "AIMS Research RA"
```

```
✓ autorite d'enregistrement creee
  nom          AIMS Research RA
  empreinte    f6b7081b230fdd66
  fichier      .ra/ra.json
```

### Creer ton compte

```bash
./sn-cli init
```

Il demande, dans l'ordre :

```
  nom complet     : Rosly Mamakem
  email           : rosly@ugb.sn
  fonction        : Chercheur
  organisation    : AIMS / UGB

  Informations personnelles a garder secretes.
  Ce n'est PAS ton mot de passe. Laisse vide pour passer.
  telephone       : +221 77 123 45 67
  adresse         : Saint-Louis
  CNI / Passeport : A1234567

  mot de passe    : ********
  confirmer       : ********
```

Tout en une ligne, sans questions :

```bash
./sn-cli init --name "Rosly Mamakem" --email "rosly@ugb.sn" \
    --role "Chercheur" --org "AIMS / UGB" \
    --telephone "+221 77 123 45 67" --adresse "Saint-Louis" --cni "A1234567"
```

Ton compte est ecrit dans `register-key/rosly-mamakem-<date>.pem`.
**Garde ce fichier** : il contient ton certificat et tes cles privees
chiffrees. Le mot de passe n'est pas recuperable.

Tu peux relancer `init` autant de fois que tu veux : chaque appel cree
un compte de plus.

---

## 2. Signer

### Un PDF le cas le plus courant

```bash
./sn-cli sign attestation.pdf --pdf --cert register-key/rosly-mamakem-20261009T211003.pem
```

```
  signataire : Rosly Mamakem <rosly@ugb.sn>

  Titre du document : Attestation de rang
  Numero d'ordre    : No 007/26
  mot de passe      : ********

✓ signe attestation.pdf · 75129 octets
  document     attestation-signe.pdf
  qr           page 1/1 · bottom-right · 100 pt
```

Le QR apparait **en bas a droite** de la page 1. Le PDF d'origine n'est
pas modifie : le QR est ajoute apres ses octets.

Sans les questions :

```bash
./sn-cli sign attestation.pdf --pdf --cert <pem> \
    --title "Attestation de rang" --ref "No 007/26"
```

Le numero d'ordre est facultatif : `--ref ""` pour l'omettre.

### Choisir ou mettre le QR

```bash
# en haut a gauche, marge de 25 points, QR de 120 points
./sn-cli sign attestation.pdf --pdf --cert <pem> \
    --position top-left --margin 25 --qr-size 120

# sur la page 3
./sn-cli sign rapport.pdf --pdf --cert <pem> --page 3
```

Positions possibles : `bottom-right` (defaut), `bottom-left`,
`top-right`, `top-left`.

### Un fichier qui n'est pas un PDF

Sans `--pdf`, le QR sort dans une image a cote :

```bash
./sn-cli sign contrat.txt --cert <pem> --title "Contrat" --ref ""
# → contrat.txt.qr.png
```

Il faut alors garder **les deux fichiers** pour verifier.

### Choisir le compte signataire

Si tu as plusieurs comptes, precise lequel :

```bash
./sn-cli sign doc.pdf --pdf --cert register-key/rosly-mamakem-20261009T211003.pem
```

`--cert` designe **le fichier de ton compte**, celui qui contient ta
cle privee. Avec un seul compte dans `register-key/`, tu peux l'omettre.

> Ne confonds pas les deux usages de `--cert` :
> - sur `sign`, `encrypt`, `decrypt` → **ton compte**, avec cle privee
> - sur `verify`, `arbitrate` → le **certificat public** de quelqu'un d'autre

---

## 3. Verifier

### Un PDF signe

```bash
./sn-cli verify attestation-signe.pdf --pdf
```

```
✓ DOCUMENT AUTHENTIQUE
  signataire   Rosly Mamakem  ed25519:b3f01e25ec5d…
               (nom declare, non certifie : passe --cert)
  titre        Attestation de rang
  numero       No 007/26
  date         2026-10-09T23:56:34+00:00
  controles    signature ✓   tag MAC ✓   revisions ✓   visuel ✓   objets ✓
```

### Avec le certificat du signataire

Pour prouver **qui** a signe, et pas seulement que le document est
intact :

```bash
./sn-cli verify attestation-signe.pdf --pdf --cert certificat-public.pem
```

```
✓ DOCUMENT AUTHENTIQUE
  signataire   Rosly Mamakem <rosly@ugb.sn>
  fonction     Chercheur · AIMS / UGB
  certificat   88a5d19591727b29 (AIMS Research RA)
  controles    signature ✓  tag MAC ✓  revisions ✓  visuel ✓  objets ✓  certificat ✓  cle liee ✓
```

`cle liee ✓` est le controle qui compte : la cle du certificat est bien
celle qui a signe ce document.

### Un fichier non-PDF

```bash
./sn-cli verify contrat.txt --qr contrat.txt.qr.png
```

### Que signifie chaque controle

| Controle | Il echoue si… |
|---|---|
| `signature` | le document a ete modifie |
| `tag MAC` | la signature a ete remplacee |
| `revisions` | du contenu a ete ajoute au PDF apres signature |
| `visuel` | l'affichage de la page a change ailleurs que sur le QR |
| `objets` | un JavaScript, un lien, une piece jointe ont ete injectes |
| `certificat` | le certificat fourni est invalide ou expire |
| `cle liee` | ce certificat n'est pas celui qui a signe |

### Le fichier `-verifie.pdf`

Chaque verification d'un PDF ecrit `<nom>-verifie.pdf`, qui contient
**exactement les octets signes**, sans le QR.

Tu n'as pas besoin de l'ouvrir en temps normal. Il sert a repondre a la
question « qu'est-ce qui a vraiment ete signe ? » en cas de litige.

**Ne le passe pas a `verify`** : il ne contient pas le QR, donc la
verification echouerait.

---

## 4. Chiffrer pour quelqu'un

Les sections precedentes signent sans chiffrer : le document reste
lisible, le QR prouve seulement qui l'a signe. C'est ce qu'il faut pour
une attestation.

Quand le document doit rester **secret**, c'est l'autre mode : un
fichier `.snc` que seul le destinataire peut ouvrir.

| | `sign` | `encrypt` |
|---|---|---|
| le document est | lisible par tous | **chiffre** |
| destinataire | tout le monde | **une personne precise** |
| sortie | QR dans le PDF | fichier `.snc` |
| pour | attestations, diplomes | rapports, contrats confidentiels |

### Chiffrer

Il te faut le certificat **public** du destinataire :

```bash
./sn-cli encrypt rapport.txt --to fatou-public.pem \
    --cert register-key/mon-compte.pem \
    --title "Rapport budgetaire" --ref "No 2026-12"
```

```
  expediteur   Rosly Mamakem <mamakemrosly@gmail.com>
  destinataire Fatou Ndiaye <fatou@ugb.sn>

  mot de passe : ********

✓ chiffre et signe rapport.txt · 76 octets
  fichier      rapport.txt.snc (540 octets)
  pour         Fatou Ndiaye <fatou@ugb.sn>
```

Le document n'apparait **nulle part** dans le `.snc` : ni en clair, ni
en fragment. Toi-meme ne peux plus le relire une fois envoye.

### Dechiffrer

```bash
./sn-cli decrypt rapport.txt.snc --cert register-key/mon-compte.pem -o rapport-recu.txt
```

```
✓ OUVERT ET AUTHENTIFIE
  document     rapport-recu.txt (76 octets)
  expediteur   Rosly Mamakem  ed25519:b3f01e25ec5d…
  titre        Rapport budgetaire
  numero       No 2026-12
```

`OUVERT ET AUTHENTIFIE` veut dire deux choses a la fois : le document a
ete dechiffre, **et** il vient bien de l'expediteur annonce. Si le
fichier a ete altere, rien ne sort du tout.

Quelqu'un d'autre qui essaie :

```
✗ ce fichier n'a pas ete chiffre pour ce compte
```

### Prouver l'origine a un tiers

C'est la propriete centrale du schema : le destinataire peut etablir
devant un arbitre que l'expediteur a bien envoye ce document **sans
l'accord de l'expediteur, et sans divulguer aucune cle privee**.

Le destinataire produit la preuve en dechiffrant :

```bash
./sn-cli decrypt rapport.txt.snc --cert register-key/mon-compte.pem \
    -o rapport-recu.txt --proof preuve.nr
```

L'arbitre n'a besoin d'aucun mot de passe :

```bash
./sn-cli arbitrate rapport.txt.snc --document rapport-recu.txt \
    --proof preuve.nr --cert rosly-public.pem
```

```
✓ ORIGINE ETABLIE
  expediteur   Rosly Mamakem <mamakemrosly@gmail.com>
  fonction     Chercheur · AIMS / UGB
  certificat   88a5d19591727b29 (AIMS Research RA)  ✓   cle liee ✓
```

Si le destinataire presente un document different de celui recu :

```
✗ ORIGINE NON ETABLIE
```

Il ne peut donc ni nier avoir recu, ni inventer un contenu.

> **Attention** : la preuve revele le contenu du document. Ne la produis
> que si tu comptes effectivement t'en servir.

### Conditions

Les deux comptes doivent etre certifies par le **meme RA** et utiliser
la **meme suite** sinon le chiffrement est refuse avec un message
explicite.

---

### Demonstration complete : Rosly envoie a Fatou

Les comptes de demonstration deja presents dans `register-key/` :

| Compte | Email | Mot de passe |
|---|---|---|
| Rosly Mamakem | `mamakemrosly@gmail.com` | `Mot2Passe!rosly` |
| Fatou Ndiaye | `fatou@ugb.sn` | `Autre!Passe99` |
| Amadou Ba | `amadou@ugb.sn` | `Mot2Passe!amadou` |

> Ce sont des comptes d'essai, crees pour la demonstration. Tes vrais
> comptes ne doivent jamais avoir leur mot de passe ecrit quelque part.

Les commandes demandent le mot de passe de maniere interactive. Pour
tout enchainer d'un bloc, on peut le passer par `SN_PASSWORD` **pour
les essais uniquement**.

#### 1. Preparer

```bash
mkdir -p try
printf 'RAPPORT CONFIDENTIEL\n\nBudget alloue : 12 500 EUR\nNe pas diffuser.\n' > try/rapport.txt

./sn-cli account export --cert register-key/fatou-ndiaye-20261009T211004.pem -o try/fatou-public.pem
./sn-cli account export --cert register-key/rosly-mamakem-20261009T211003.pem -o try/rosly-public.pem
```

#### 2. Rosly chiffre pour Fatou

```bash
SN_PASSWORD="Mot2Passe!rosly" ./sn-cli encrypt try/rapport.txt \
    --to try/fatou-public.pem --cert register-key/rosly-mamakem-20261009T211003.pem \
    --title "Rapport budgetaire" --ref "No 2026-12"
```

```
  expediteur   Rosly Mamakem <mamakemrosly@gmail.com>
  destinataire Fatou Ndiaye <fatou@ugb.sn>

✓ chiffre et signe rapport.txt · 66 octets
  fichier      try/rapport.txt.snc (530 octets)
```

Verifier que rien ne fuit :

```bash
grep -c "12 500" try/rapport.txt.snc    # → 0, aucune trace
```

#### 3. Amadou essaie d'ouvrir refuse

```bash
SN_PASSWORD="Mot2Passe!amadou" ./sn-cli decrypt try/rapport.txt.snc \\
    --cert register-key/amadou-ba-20261009T212209.pem
```

```
✗ ce fichier n'a pas ete chiffre pour ce compte
```

#### 4. Fatou ouvre, et garde la preuve

```bash
SN_PASSWORD="Autre!Passe99" ./sn-cli decrypt try/rapport.txt.snc \
    --cert register-key/fatou-ndiaye-20261009T211004.pem -o try/recu.txt --proof try/preuve.nr
```

```
✓ OUVERT ET AUTHENTIFIE
  document     try/recu.txt (66 octets)
  expediteur   Rosly Mamakem  ed25519:b3f01e25ec5d…
  titre        Rapport budgetaire
  numero       No 2026-12
  preuve       try/preuve.nr
```

```bash
cat try/recu.txt     # le document d'origine, a l'identique
```

#### 5. Rosly nie l'arbitre tranche

Aucun mot de passe ici : l'arbitre n'est ni Rosly ni Fatou.

```bash
./sn-cli arbitrate try/rapport.txt.snc --document try/recu.txt \
    --proof try/preuve.nr --cert try/rosly-public.pem
```

```
✓ ORIGINE ETABLIE
  expediteur   Rosly Mamakem <mamakemrosly@gmail.com>
  fonction     Chercheur · AIMS / UGB
  certificat   88a5d19591727b29 (AIMS Research RA)  ✓   cle liee ✓
```

#### 6. Fatou essaie de falsifier le contenu refuse

```bash
printf 'RAPPORT CONFIDENTIEL\n\nBudget alloue : 99 000 EUR\nNe pas diffuser.\n' > try/faux.txt

./sn-cli arbitrate try/rapport.txt.snc --document try/faux.txt \
    --proof try/preuve.nr --cert try/rosly-public.pem
```

```
✗ ORIGINE NON ETABLIE
  ce document ne correspond pas a ce fichier scelle
```

#### 7. Le fichier scelle a ete altere

```bash
cp try/rapport.txt.snc try/altere.snc
printf '\x01' | dd of=try/altere.snc bs=1 seek=400 count=1 conv=notrunc 2>/dev/null

SN_PASSWORD="Autre!Passe99" ./sn-cli decrypt try/altere.snc --cert register-key/fatou-ndiaye-20261009T211004.pem
```

```
✗ CONTENU REFUSE
  la signature ou le tag ne correspondent pas
```

#### Resume

| Etape | Resultat | Code |
|---|---|---|
| Fatou ouvre | `✓ OUVERT ET AUTHENTIFIE` | 0 |
| Amadou essaie | refuse | 1 |
| Rosly essaie de relire son envoi | refuse | 1 |
| Arbitrage, vrai document | `✓ ORIGINE ETABLIE` | 0 |
| Arbitrage, document falsifie | `✗ ORIGINE NON ETABLIE` | 1 |
| Fichier altere | `✗ CONTENU REFUSE` | 1 |

## 5. Comptes et certificats

### Lister ses comptes

```bash
./sn-cli account list
```

```
2 compte(s)
  ✓ rosly-mamakem-20261009T211003.pem
      Rosly Mamakem <rosly@ugb.sn> · Chercheur · AIMS / UGB
      serie 88a5d19591727b29 · valide jusqu'au 2028-10-08
```

### Voir un compte

```bash
./sn-cli account show --cert register-key/rosly-mamakem-20261009T211003.pem
```

### Partager son certificat

Pour que les autres puissent verifier tes signatures, donne-leur ton
certificat **public** il ne contient aucune cle privee :

```bash
./sn-cli account export --cert register-key/rosly-mamakem-20261009T211003.pem -o rosly-public.pem
```

### Ouvrir un certificat

Affiche la partie publique, puis demande le mot de passe pour la partie
masquee :

```bash
./sn-cli open register-key/rosly-mamakem-20261009T211003.pem
```

```
┌─ informations publiques
│  nom           Rosly Mamakem
│  email         rosly@ugb.sn
│  fonction      Chercheur
│  controles     signature RA ✓   periode ✓   RA local ✓   en-tetes ✓
├─ informations masquees mot de passe requis
│  telephone     +221 77 123 45 67
│  adresse       Saint-Louis
│  cni_passeport A1234567
│  sk_sd         3be8a6983bac4480… (32 octets, --reveal pour tout voir)
└─ ouvert
```

```bash
./sn-cli open mon-compte.pem --public    # sans mot de passe, partie publique seule
./sn-cli open mon-compte.pem --reveal    # affiche les cles privees en entier
```

### Verifier un certificat recu

```bash
./sn-cli ra verify rosly-public.pem
```

Repond `✓ IDENTITE CERTIFIEE` si le RA l'a bien emis et qu'il est
toujours valide.

### Voir le RA

```bash
./sn-cli ra show
```

---

## 6. Regarder le contenu d'une preuve

```bash
./sn-cli inspect --qr contrat.txt.qr.png
```

Affiche les champs bruts : cles publiques, signature, tag, les quatre
cles de session. Utile pour comprendre ou deboguer, pas pour verifier.

---

## 7. Codes de sortie

Pour utiliser `sn-cli` dans un script :

| Code | Signification |
|---|---|
| `0` | tout est bon |
| `1` | document non authentique, ou certificat invalide |
| `2` | erreur : fichier illisible, mauvais mot de passe, preuve introuvable |

```bash
if ./sn-cli verify doc.pdf --pdf --cert public.pem > /dev/null 2>&1; then
    echo "authentique"
else
    echo "refuse"
fi
```

---

## 8. Mode Cryptographe

`ra init` et `init` affichent une banniere ASCII portant toujours le nom
du logiciel et ses auteurs :

```
   ███████╗███╗   ██╗
   ██╔════╝████╗  ██║     S I G N C R Y P T I O N
   ███████╗██╔██╗ ██║
   ╚════██║██║╚██╗██║     insider secure · NINR
   ███████║██║ ╚████║
   ╚══════╝╚═╝  ╚═══╝

   Signcryption, Author <Togde & Sarr>
   « L'identite publique se montre, la cle privee se tait. »
```

Les commandes qui travaillent sur les cles deroulent leurs etapes
reelles :

```
  ┌─ signcryption ────────────────────────────────
  ✓ Controle du certificat du destinataire
  ✓ Ouverture du coffre                      [scrypt]
  ✓ Encapsulation vers le destinataire       [c1]
  ✓ Chiffrement du document                  [ChaCha20]
  ✓ Signature de l'empreinte                 [sigma]
```

Chaque ligne correspond a une operation reelle du schema. Le spinner et
l'epigraphe changent a chaque execution.

L'affichage est **automatiquement coupe** quand la sortie n'est pas un
terminal script, pipe, redirection pour que le texte utile reste
exploitable. Pour le couper aussi en terminal :

```bash
./sn-cli --no-banner init
SN_NO_BANNER=1 ./sn-cli init
```

## 9. Options globales

| Option | Effet |
|---|---|
| `--register <dossier>` | autre dossier de comptes (defaut `register-key/`) |
| `--ra-home <dossier>` | autre dossier de RA (defaut `.ra/`) |
| `--no-banner` | couper la banniere et les animations |

Pratique pour tester sans toucher a tes vrais comptes :

```bash
./sn-cli --register /tmp/essai --ra-home /tmp/essai-ra ra init
./sn-cli --register /tmp/essai --ra-home /tmp/essai-ra init --name Test ...
```

---

## 10. Problemes courants

**`2 comptes disponibles ; precise lequel`**
Ajoute `--cert <fichier.pem>`, le chemin de ton compte dans
`register-key/`. `./sn-cli account list` te donne la liste.

**`mot de passe incorrect`**
Trois essais, puis la commande s'arrete. Le mot de passe n'est pas
recuperable : si tu l'as perdu, il faut recreer un compte.

**`aucune preuve SN trouvee dans ...`**
Le PDF n'a pas ete signe, ou tu as passe le mauvais fichier verifie
que c'est bien le `-signe.pdf` et pas l'original ni le `-verifie.pdf`.

**`preuve en version 1, cet outil lit la version 3`**
Le QR vient d'une version precedente de l'outil. Refais la signature.

**`un RA existe deja`**
C'est voulu. Le recreer invaliderait tous les certificats emis.

**`cette preuve a ete emise pour un fichier hors PDF`**
Tu utilises `--pdf` avec le QR d'un fichier signe sans `--pdf`.

---

## 11. A savoir

**Le QR contient de quoi dechiffrer le document.** C'est inherent au
schema : la preuve de non-repudiation contient les cles de session. Ne
publie un QR que pour un document destine a etre vu.

**`sign` demande le mot de passe, `verify` jamais.** La verification
n'utilise que des cles publiques n'importe qui peut verifier.

**Le certificat public ne contient aucun secret.** Tu peux l'envoyer par
mail, le publier, le joindre a un document.

**Les donnees privees (telephone, CNI) ne sont pas dans le certificat**
et ne sont pas signees par le RA. Elles sont chiffrees par ton mot de
passe et visibles uniquement avec `sn open`.

---

## 12. Toutes les commandes

```
sn ra init [--name] [--suite]          creer le RA (une fois)
sn ra show                             afficher le RA
sn ra verify <cert.pem>                controler un certificat

sn init [--name --email --role --org]  creer un compte
        [--telephone --adresse --cni] [--private CLE=VAL] [--suite]

sn account list                        lister les comptes
sn account show [--cert]               detailler un compte
sn account export [--cert] -o          exporter le certificat public

sn sign <fichier> [--cert]             signer sans chiffrer
        [--pdf] [--page] [--position] [--margin] [--qr-size]
        [--title] [--ref] [-o]

sn encrypt <fichier> --to <cert.pem>   chiffrer pour un destinataire
        [--cert] [--title] [--ref] [-o]
sn decrypt <fichier.snc> [--cert]      ouvrir un .snc
        [--proof <fichier>] [-o]
sn arbitrate <fichier.snc> --document <f> --proof <f> [--cert]

sn verify <fichier> [--pdf|--qr|--snr|--payload] [--cert]
sn open <cert.pem> [--public] [--reveal]
sn inspect [--qr|--snr|--payload]
```

Chaque commande accepte `--help`.
