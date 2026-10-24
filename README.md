# SN Signcryption document signing with QR verification

A reference implementation of the **SN** signcryption scheme from:

> Ngarenon Togde, Augustin P. Sarr.
> *An Efficient Generic Insider Secure Signcryption with Non-Interactive
> Non-Repudiation.* Laboratoire ACCA, Université Gaston Berger, Saint-Louis.

Sign a file, get a QR code, and later prove from the QR code plus the
original file whether the document is unmodified and who signed it.

```
$ sn-cli ra init --name "AIMS Research RA"
$ sn-cli init                              # identity + password, certificate signed by the RA
$ sn-cli sign contrat.txt --as rosly@ugb.sn    # asks for the password
$ sn-cli verify contrat.txt --qr contrat.txt.qr.png --cert register-key/rosly-*.pem
✓ DOCUMENT AUTHENTIQUE
  signataire   Rosly Mamakem <rosly@ugb.sn>
  fonction     Chercheur · AIMS / UGB
  certificat   88a5d19591727b29 (AIMS Research RA)
  controles    signature ✓   tag MAC ✓   certificat ✓   cle liee ✓
```

CLI messages are in French; the code and this README are in English.

## Install

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./sn-cli --help
```

## Register Authority (RA)

The tool runs a local **Register Authority**. It owns a key pair, fixes
`tau0` (the scheme's public domain parameter) for everyone it registers,
and signs certificates binding a person's identity to their two SN
public keys.

```bash
./sn-cli ra init --name "AIMS Research RA"   # once, ever
./sn-cli ra show
```

The RA lives in the hidden `.ra/` directory: `ra.json` (0600) plus an
`issued/` log of every certificate. Re-running `ra init` is refused —
replacing the RA would invalidate every certificate it has signed.

Two operations, as requested:

| | |
|---|---|
| **RA-sign** | the RA issues and signs a certificate (`ra_sign`, called by `sn init`) |
| **RA-verify** | anyone checks a certificate against the RA public key, and so learns who `pk_sd` belongs to (`ra_verify`, `sn ra verify`) |

RA-verify needs no secret at all — the RA public key is enough.

## Accounts

`sn init` asks for the signer's details and a password, then has the RA
sign the certificate. **It can be run as many times as you like**: each
run writes a new file, so several accounts coexist.

```bash
./sn-cli init
  nom complet     : Rosly Mamakem
  email           : rosly@ugb.sn
  fonction        : Chercheur
  organisation    : AIMS / UGB
  mot de passe    :
  confirmer       :

→ register-key/rosly-mamakem-20261009T211003.pem
```

```bash
./sn-cli account list                        # every account, with its RA check
./sn-cli account show --as rosly@ugb.sn
./sn-cli account export --as rosly@ugb.sn -o public.pem   # certificate only
```

### The .pem file

One file per account, in `register-key/<name>-<timestamp>.pem`, holding
two PEM blocks:

```
-----BEGIN SN CERTIFICATE-----
Name: Rosly Mamakem
Email: rosly@ugb.sn
Role: Chercheur
Organization: AIMS / UGB
Serial: 88a5d19591727b29
Issuer: AIMS Research RA
Issuer-Fingerprint: f6b7081b230fdd66
Not-Before: 2026-10-09T21:10:03+00:00
Not-After: 2028-10-08T21:10:03+00:00

<base64: the signed certificate body>
-----END SN CERTIFICATE-----
-----BEGIN SN ENCRYPTED PRIVATE KEY-----
<base64: sk_sd and sk_rcv, scrypt + AES-256-GCM>
-----END SN ENCRYPTED PRIVATE KEY-----
```

Public identity is readable at a glance; the private keys need the
password. The certificate serial is bound in as AEAD associated data, so
one account's vault cannot be grafted onto another's certificate.

**The headers are outside the base64, so they are not signed.** They
exist so a human can read the file. `Certificate.from_pem` compares every
header against the signed body and reports any that disagree, and
RA-verify then refuses the certificate — so a doctored header is caught
rather than believed.

**`sign` asks for the password. `verify` never does.**

## Opening a certificate

`sn open` shows the public part first, then asks for the password to
reveal what is hidden:

```bash
./sn-cli open register-key/amadou-ba-20261009T212209.pem
┌─ informations publiques — amadou-ba-20261009T212209.pem
│  nom           Amadou Ba
│  email         amadou@ugb.sn
│  fonction      Enseignant-chercheur
│  organisation  UGB / LACCA
│  controles     signature RA ✓   periode ✓   RA local ✓   en-tetes ✓
├─ informations masquees — mot de passe requis
│  telephone     +221 77 123 45 67
│  CNI           1234567890123
│  adresse       Saint-Louis, Senegal
│  sk_sd         3be8a6983bac4480… (32 octets, --reveal pour tout voir)
│  sk_rcv        789730265f5c692f… (32 octets, --reveal pour tout voir)
└─ ouvert
```

- `--public` stops at the public part and never asks for a password.
- `--reveal` prints the private keys in full, with a warning.
- On an exported certificate (no key block) it says so and stops.
- A wrong password leaks nothing: the public part still shows, the
  hidden part does not.

### Private personal data

Fields that should not be public can go in the vault instead of the
certificate:

```bash
./sn-cli init --telephone "+221 77 123 45 67" --adresse "Saint-Louis" --cni "A1234567"
```

Interactive `sn init` asks for those same three, each optional. Any
other field can be added with `--private cle=valeur`. These
fields are **not** in the certificate and **not** signed by the RA: they
are encrypted under the password and only `sn open` shows them. The
public identity (name, email, role, organization) stays in the
certificate, where the RA signature covers it.

Accounts created without private data still open normally — the vault
carries two fields instead of three.

## Signing a document

```bash
./sn-cli sign contrat.txt --cert register-key/rosly-mamakem-20261009T211003.pem
  signataire : Rosly Mamakem <mamakemrosly@gmail.com>
  certificat : rosly-mamakem-20261009T211003.pem

  Titre du document : Contrat de prestation
  Numero d'ordre    : 2026-001
  mot de passe      :
```

The password unlocks `sk_sd` from the certificate file, and that key
signs. Title and order number are **part of `m`**, so the signature
covers them: changing either one afterwards invalidates the signature
just like changing a byte of the document. The order number is optional.

Non-interactive form:

```bash
./sn-cli sign contrat.txt --cert <pem> --title "Contrat de prestation" --ref "2026-001"
```

Verification reads the QR code and checks the signature:

```bash
./sn-cli verify contrat.txt --qr contrat.txt.qr.png
✓ DOCUMENT AUTHENTIQUE
  titre        Contrat de prestation
  numero       2026-001
  controles    signature ✓   tag MAC ✓
```

## Signing a PDF with a visible QR code

The obvious approach fails: sign the PDF, stamp the QR on it, and the
file has changed — the signature no longer verifies.

`--pdf` solves it with an **incremental update**. PDF allows appending
objects at the end of a file without touching a single byte before, so
the N bytes of the original are what gets signed, and the QR is added
after them:

```
[──── PDF original, N octets ────][──── ajout : image QR ────]
 \________ signed ________________/
```

Position in the file has nothing to do with position on the page: the
reader follows the last xref and draws the QR wherever you asked.

```bash
./sn-cli sign attestation.pdf --pdf --cert register-key/fatou-*.pem \
    --title "Attestation de rang" --ref "No 007/26"

✓ signe attestation.pdf · 75129 octets
  document     attestation-signe.pdf
  qr           page 1/1 · bottom-right · 100 pt
  signe        75129 octets sur 86680 (+11551 pour le QR)
```

Defaults: page 1, bottom-right, 10 pt margins, 100 pt square. Change
them with `--page`, `--position` (the four corners), `--margin`,
`--qr-size`.

Verification reads the QR straight out of the PDF — one file, nothing
else to carry:

```bash
./sn-cli verify attestation-signe.pdf --pdf --cert fatou-public.pem
✓ DOCUMENT AUTHENTIQUE
  signe        75129 octets sur 86680 (+11551 ajoutes apres signature)
  verifie      attestation-signe-verifie.pdf
  controles    signature ✓   tag MAC ✓   certificat ✓   cle liee ✓
```

`embed_qr` re-reads what it wrote and refuses to produce a file whose
prefix drifted, so a future pypdf that stopped writing incrementally
would fail loudly instead of emitting silently invalid signatures.

### Content appended after signing

Bytes **after** N are not signed, so an attacker can append content
without touching a signed byte (*PDF shadow attacks*, Mladenov et al.
2019). They cannot be authenticated — but we know exactly what they are
allowed to contain, and that is checkable with no user inspection.

Three checks run on the unsigned tail:

| Check | What it catches |
|---|---|
| **revisions** | each incremental update ends in `%%EOF`; exactly one more than the signed prefix is allowed |
| **visuel** | the page is rendered from the signed prefix and from the received file; the pixels may differ only inside the QR, located by the decoder itself |
| **objets** | the added revision must introduce no `/JavaScript`, `/Annots`, `/EmbeddedFile`, `/OpenAction`, `/Launch`, `/AcroForm`… |

```
  controles    signature ✓   tag MAC ✓   revisions ✓   visuel ✓   objets ✓
```

The three are not redundant — each one catches an attack the others
miss:

| Attack | revisions | visuel | objets |
|---|---|---|---|
| banner in a *separate* revision | ✗ | ✗ | ✓ |
| banner **merged** into the QR revision | ✓ | **✗** | ✓ |
| JavaScript **merged** into the QR revision | ✓ | ✓ | **✗** |
| invisible phishing link | ✗ | ✓ | **✗** |
| malicious attachment | ✗ | ✓ | **✗** |

The visual check stores nothing and trusts nothing: the permitted
region is the QR as the decoder locates it in the rendered page, so a
forged `prefix_len` cannot widen it. Rendering is deterministic — zero
pixels of drift between two renders of the same file — and the scale
adapts when a small QR is not locatable at the first one.

`embed_qr` also re-reads what it wrote and refuses to emit a file whose
prefix drifted or that gained more than one revision.

**What is still not covered.** If someone hands you a PDF that is
*already* booby-trapped — a hidden layer, a form field with two values —
and you sign it in good faith, the signature is honestly valid and the
render of the signed prefix already contains the trap. No signature
scheme can prevent that; flatten documents before signing them.

For the record, verification still writes `<name>-verifie.pdf` with
exactly the signed bytes, so the evidence can always be inspected
directly. But it is no longer the only line of defence.

## Linking a signature to a certified identity

A QR code proves the document was signed by the holder of `pk_sd`. Pass
`--cert` to also prove *who that is*:

```bash
./sn-cli verify contrat.txt --qr contrat.txt.qr.png --cert register-key/rosly-*.pem
✓ DOCUMENT AUTHENTIQUE
  signataire   Rosly Mamakem <rosly@ugb.sn>
  fonction     Chercheur · AIMS / UGB
  certificat   88a5d19591727b29 (AIMS Research RA)
  controles    signature ✓   tag MAC ✓   certificat ✓   cle liee ✓
```

`cle liee` is the check that the certificate's `pk_sd` is the key that
actually signed this document. Without `--cert`, the signer name shown
comes from the signed metadata and is marked as uncertified.

Certificates are plain text files. There is no QR code for a certificate.

## The scheme

[`sn/scheme.py`](sn/scheme.py) follows the pseudocode on p. 9 of the
paper line for line. All seven algorithms are present:

| Algorithm | Returns |
|---|---|
| `setup` | `dp = (dp_K, dp_S, E, Prf, H, tau0)` |
| `gen_sd` / `gen_rcv` | sender signing keys / receiver KEM keys |
| `sc` | `C = (t, sigma, c1, c2)` |
| `usc` | `m`, or `None` for the error symbol |
| `n` | `nr = (tau1, tau1', tau2, tau2')` |
| `pv` | `0` / `1`, with no private key and no interaction |

`Sc` signs `m-hat = H(tau0, (pk_sd, tau2, tau2', tau3, c1, c2, pk_rcv))`,
never the message itself. Because `tau2`, `tau2'` and
`tau3 = Prf(tau2, m)` all come from the encapsulated key, nobody can
reconstruct `m-hat` — not even the sender afterwards — without the
receiver's private key. That is what makes the construction insider
secure, and the tag `t = Prf(tau1', sigma)` is what blocks the re-signing
attack. [`tests/test_attacks.py`](tests/test_attacks.py) demonstrates
that attack and shows the tag is precisely what stops it.

## Suites

The construction is generic over five primitives, so they sit behind
interfaces in [`sn/primitives/`](sn/primitives/) and a suite is just a
choice of five.

| | classical | pq |
|---|---|---|
| KEM (IND-CCA) | X25519 DHKEM | ML-KEM-768 |
| Signature (sUF-CMA) | Ed25519 | ML-DSA-65 |
| Symmetric | ChaCha20 | ChaCha20 |
| PRF / keyed hash | HMAC-SHA256 | HMAC-SHA256 |
| Evidence size | **354 B** → fits a QR code | **7727 B** → sidecar `.snr` file |

Not ECDSA: it is malleable (`s -> n-s`), so it is not sUF-CMA and would
break Theorem 2.

## Design notes

**`c2` is not in the QR code.** It is the size of the whole document.
Instead ℰ is pinned to a deterministic, length-preserving stream cipher,
so a verifier holding the original file recomputes `c2 = E(tau1, m)` and
then runs `PV` unchanged. Soundness is unaffected: for `m' != m` both
`c2' != c2` and `tau3' != tau3`, so `m-hat` differs and the signature
fails — the argument of Theorem 3. The cost is that this deployment gives
up the randomized encryption the paper permits (an advantage it claims
over CMSM2, p. 18).

Consequently `PV`'s plaintext check (line 32) is vacuous here, and the
CLI does not display it as a passing check.

**Every field is length-prefixed** ([`sn/codec.py`](sn/codec.py)). The
paper requires only that tuples parse unambiguously (p. 2), but `c1` and
`c2` are adjacent and variable length in the hash input, so plain
concatenation would hand over a free collision.

**Public keys are validated.** The proofs omit this for readability
(p. 10); the dynamic multi-user model assumes no key registration, so it
is exactly where real attacks land.

**Metadata is bound** by being part of `m`:
`m = (timestamp, filename, signer, document)`. The scheme is untouched —
whatever is in `m` is what the signature covers.

**The evidence discloses the document.** `nr` contains `tau1`, so anyone
holding the QR code can decrypt `c2`. This is inherent to NINR: settling
a dispute costs that message's confidentiality. Publish evidence only for
documents meant to be public.

**Standard model, with an asterisk.** The paper's headline is that SN
needs no random oracle and no registered-key model. Both suites here use
a KEM whose own IND-CCA proof is in the ROM (DHKEM directly, ML-KEM via
the Fujisaki–Okamoto transform). The *construction* stays standard-model;
the instantiation does not. A genuinely end-to-end standard-model
instance would need something like Cramer–Shoup — which is what the
pluggable KEM interface is for.

## Tests

```bash
.venv/bin/python -m pytest -v
```

Covers consistency, NINR, soundness, tampering of each field of `C`,
wrong keys, truncation, the re-signing attack, encoding ambiguity, and
QR round-trips.

QR decoding uses zxing-cpp. OpenCV's `QRCodeDetector` was measured
failing 10–35% of the time on codes this dense, at every pixel scale;
`tests/test_evidence.py::test_qr_decoding_is_reliable` guards against
reintroducing that.

## Scope

Research and teaching code for studying the paper — not production
crypto. No timestamping authority, no revocation, no key distribution:
the signer's public key travels in the QR code, so trusting that it
belongs to the named signer is out of band.
