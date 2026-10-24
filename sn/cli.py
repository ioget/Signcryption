"""Interface en ligne de commande."""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
from pathlib import Path

from . import banner, keystore, pdfcheck, pdfsign, pem, qr, vault
from . import ra as ra_mod
from .evidence import Evidence, Metadata, build_message
from .ra import Certificate, Subject
from .sealed import Sealed
from .scheme import n as nr_generate
from .scheme import Keys, sc

_COLOR = sys.stdout.isatty()
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _c(t: str, code: str) -> str:
    return f"\033[{code}m{t}\033[0m" if _COLOR else t


green = lambda t: _c(t, "32")   # noqa: E731
red = lambda t: _c(t, "31")     # noqa: E731
dim = lambda t: _c(t, "2")      # noqa: E731
bold = lambda t: _c(t, "1")     # noqa: E731
cyan = lambda t: _c(t, "36")    # noqa: E731
mark = lambda b: green("✓") if b else red("✗")  # noqa: E731


def _fp(pk: bytes, algo: str) -> str:
    return f"{algo}:{pk.hex()[:12]}…"


def _ra_dir(args):
    return Path(args.ra_home) if args.ra_home else None


def _reg_dir(args):
    return Path(args.register) if args.register else None


# --- saisie -----------------------------------------------------------------


def ask(label: str, value: str | None, validator=None) -> str:
    if value:
        return value
    while True:
        got = input(f"  {label:16s}: ").strip()
        if not got:
            print(dim("    champ obligatoire"))
        elif validator and not validator(got):
            print(dim("    format invalide"))
        else:
            return got


def ask_optional(label: str, value: str | None) -> str:
    """Champ facultatif : l'option l'emporte, sinon on demande.

    Sans terminal (script, pipe), on n'essaie pas de lire stdin et le
    champ reste vide plutot que de bloquer.
    """
    if value is not None:
        return value
    try:
        return input(f"  {label:18s}: ").strip()
    except (OSError, EOFError):
        return ""


def ask_password(confirm: bool = False) -> str:
    """SN_PASSWORD court-circuite la saisie : c'est pour les tests."""
    env = os.environ.get("SN_PASSWORD")
    if env is not None:
        return env
    while True:
        first = getpass.getpass("  mot de passe    : ")
        if not confirm:
            return first
        warning = vault.check_strength(first)
        if warning:
            print(dim(f"    {warning}"))
            continue
        if first != getpass.getpass("  confirmer       : "):
            print(dim("    les deux saisies different"))
            continue
        return first


def _unlock(account: keystore.Account) -> keystore.Unlocked:
    for attempt in (1, 2, 3):
        try:
            return account.unlock(ask_password())
        except vault.BadPassword:
            left = 3 - attempt
            if not left or os.environ.get("SN_PASSWORD") is not None:
                raise
            print(red(f"  mot de passe incorrect ({left} essai(s) restant)"))
    raise vault.BadPassword("mot de passe incorrect")


def _pick(args) -> keystore.Account:
    """Le compte a utiliser : son fichier .pem, ou l'unique du registre."""
    return keystore.resolve(args.cert, _reg_dir(args))


# --- RA ---------------------------------------------------------------------


def cmd_ra_init(args) -> int:
    banner.banniere("ra")
    try:
        ra = ra_mod.ra_init(args.name, suite=args.suite, directory=_ra_dir(args))
    except FileExistsError as exc:
        print(red(f"✗ {exc}"))
        return 1
    banner.etapes("ra")
    print(green("✓ autorite d'enregistrement creee"))
    print(f"  nom          {ra.name}")
    print(f"  suite        {ra.suite}")
    print(f"  empreinte    {cyan(ra.fingerprint())}")
    print(f"  cle publique {ra.pk.hex()}")
    print(f"  tau0         {ra.tau0.hex()}")
    print(f"  fichier      {ra_mod.ra_path(_ra_dir(args))}")
    print()
    print(dim("  La cle privee du RA n'est protegee que par les droits Unix"))
    print(dim("  0600. Qui peut lire ce fichier peut signer des certificats."))
    banner.conclusion("ra")
    return 0


def cmd_ra_show(args) -> int:
    ra = ra_mod.ra_load(_ra_dir(args))
    issued = (_ra_dir(args) or ra_mod.RA_DIR) / "issued"
    count = len(list(issued.glob("*.pem"))) if issued.exists() else 0
    print(bold("autorite d'enregistrement"))
    print(f"  nom          {ra.name}")
    print(f"  suite        {ra.suite}")
    print(f"  empreinte    {cyan(ra.fingerprint())}")
    print(f"  cle publique {ra.pk.hex()}")
    print(f"  tau0         {ra.tau0.hex()}")
    print(f"  creee le     {ra.created}")
    print(f"  certificats  {count} emis")
    return 0


def cmd_ra_verify(args) -> int:
    """RA-verify : controle un certificat avec la cle publique du RA."""
    try:
        ra = ra_mod.ra_load(_ra_dir(args))
    except FileNotFoundError:
        ra = None
    try:
        cert, result = ra_mod.ra_verify_file(Path(args.certificate), ra)
    except (pem.PemError, ValueError) as exc:
        print(red(f"✗ certificat illisible : {exc}"))
        return 2

    print(green(bold("✓ IDENTITE CERTIFIEE")) if result.valid
          else red(bold("✗ CERTIFICAT NON VALIDE")))
    s = cert.subject
    print(f"  nom          {s.name}")
    print(f"  email        {s.email}")
    print(f"  fonction     {s.role}")
    print(f"  organisation {s.organization}")
    print(f"  serie        {cert.serial}")
    print(f"  empreinte    {cyan(cert.fingerprint())}")
    print(f"  cle sign.    {cert.pk_sd.hex()}")
    print(f"  validite     {cert.not_before[:10]} → {cert.not_after[:10]}")
    print(f"  emis par     {cert.issuer} ({cert.issuer_fingerprint()})")
    print()
    line = f"  controles    signature RA {mark(result.signature_ok)}   periode {mark(result.period_ok)}"
    if result.issuer_matches is None:
        line += dim("   RA local introuvable")
    else:
        line += f"   RA local {mark(result.issuer_matches)}"
    line += f"   en-tetes {mark(result.headers_ok)}"
    print(line)
    for problem in result.problems:
        print(red(f"  ! {problem}"))
    return 0 if result.valid else 1


# --- comptes ----------------------------------------------------------------


# Champs prives proposes a la creation : fixes, pour que la saisie reste
# simple et que tous les comptes aient la meme forme.
PRIVATE_FIELDS = [
    ("telephone", "telephone", "telephone"),
    ("adresse", "adresse", "adresse"),
    ("cni_passeport", "CNI / Passeport", "cni"),
]


def _collect_private(args) -> dict[str, str]:
    """Donnees personnelles qui vont dans le coffre, pas dans le certificat.

    Le RA ne les signe pas et elles ne sont lisibles qu'avec le mot de
    passe ; elles servent a garder des informations sensibles a cote de
    l'identite publique.  Tous les champs sont facultatifs.
    """
    private: dict[str, str] = {}
    for item in args.private or []:
        key, sep, value = item.partition("=")
        if not sep or not key.strip():
            raise SystemExit(f"--private attend cle=valeur, recu {item!r}")
        private[key.strip()] = value.strip()

    for key, _, option in PRIVATE_FIELDS:
        given = getattr(args, option, None)
        if given:
            private[key] = given

    if private or args.name:  # mode non interactif : on ne demande rien
        return private

    print()
    print(dim("  Informations personnelles a garder secretes."))
    print(dim("  Ce n'est PAS ton mot de passe. Laisse vide pour passer."))
    for key, label, _ in PRIVATE_FIELDS:
        value = input(f"  {label:16s}: ").strip()
        if value:
            private[key] = value
    return private


def cmd_init(args) -> int:
    try:
        ra = ra_mod.ra_load(_ra_dir(args))
    except FileNotFoundError as exc:
        print(red(f"✗ {exc}"))
        return 2

    banner.banniere("compte")
    print(bold("Creation d'un compte sn-signcryption"))
    print(dim(f"  enregistre par : {ra.name} ({ra.fingerprint()})"))
    print()
    subject = Subject(
        name=ask("nom complet", args.name),
        email=ask("email", args.email, validator=lambda v: bool(_EMAIL.match(v))),
        role=ask("fonction", args.role),
        organization=ask("organisation", args.org),
    )
    private = _collect_private(args)
    print()
    password = ask_password(confirm=True)

    print()
    banner.etapes("compte")
    account = keystore.create(
        subject, password, ra, suite=args.suite,
        directory=_reg_dir(args), ra_directory=_ra_dir(args),
        private=private,
    )
    cert = account.cert
    print(green("✓ compte cree, certificat signe par le RA"))
    print(f"  sujet        {cert.subject}")
    print(f"  serie        {cert.serial}")
    print(f"  suite        {cert.suite}")
    print(f"  cle sign.    {_fp(cert.pk_sd, account.dp.suite.sig.name)}")
    print(f"  validite     {cert.not_before[:10]} → {cert.not_after[:10]}")
    print(f"  certificat   {bold(str(account.path))}")
    print()
    print(dim("  Le fichier contient ton certificat (lisible) et tes cles"))
    print(dim("  privees chiffrees par ton mot de passe. Garde-le : il est"))
    print(dim("  ton compte. Le mot de passe n'est pas recuperable."))
    banner.conclusion("compte")
    return 0


def cmd_account_list(args) -> int:
    paths = keystore.discover(_reg_dir(args))
    if not paths:
        print(dim(f"aucun compte dans {keystore.register_dir(_reg_dir(args))}"))
        return 0
    try:
        ra = ra_mod.ra_load(_ra_dir(args))
    except FileNotFoundError:
        ra = None
    print(bold(f"{len(paths)} compte(s)"))
    for path in paths:
        try:
            account = keystore.load(path)
        except (pem.PemError, ValueError) as exc:
            print(f"  {red('✗')} {path.name}  {dim(str(exc))}")
            continue
        result = ra_mod.ra_verify(
            account.cert, ra, list(account.header_problems)
        )
        s = account.subject
        print(f"  {mark(result.valid)} {path.name}")
        print(dim(f"      {s.name} <{s.email}> · {s.role} · {s.organization}"))
        print(dim(f"      serie {account.cert.serial} · "
                  f"valide jusqu'au {account.cert.not_after[:10]}"))
    return 0


def cmd_account_show(args) -> int:
    account = _pick(args)
    try:
        ra = ra_mod.ra_load(_ra_dir(args))
    except FileNotFoundError:
        ra = None
    result = ra_mod.ra_verify(account.cert, ra, list(account.header_problems))
    cert = account.cert
    print(bold("compte"))
    print(f"  fichier      {account.path}")
    print(f"  nom          {cert.subject.name}")
    print(f"  email        {cert.subject.email}")
    print(f"  fonction     {cert.subject.role}")
    print(f"  organisation {cert.subject.organization}")
    print(f"  serie        {cert.serial}")
    print(f"  pk_sd        {cert.pk_sd.hex()}")
    print(f"  pk_rcv       {cert.pk_rcv.hex()}")
    print(f"  validite     {cert.not_before[:10]} → {cert.not_after[:10]}")
    print(f"  certificat   {mark(result.valid)}")
    for problem in result.problems:
        print(red(f"  ! {problem}"))
    return 0 if result.valid else 1


def cmd_cert_export(args) -> int:
    """Exporte le certificat seul, sans le bloc de cle privee."""
    account = _pick(args)
    text = account.cert.to_pem()
    if args.out:
        Path(args.out).write_text(text)
        print(green("✓ certificat exporte"), dim(args.out))
        print(dim("  ce fichier est public : il ne contient aucune cle privee"))
    else:
        print(text, end="")
    return 0


def _mask(value: bytes, reveal: bool) -> str:
    """Une cle privee ne s'affiche en entier que sur demande explicite."""
    if reveal:
        return value.hex()
    return f"{value.hex()[:16]}\u2026 ({len(value)} octets, --reveal pour tout voir)"


def cmd_open(args) -> int:
    """Ouvre un .pem : partie publique, puis partie masquee sous mot de passe."""
    path = Path(args.certificate)
    try:
        text = path.read_text()
    except OSError as exc:
        print(red(f"✗ {exc}"))
        return 2
    try:
        cert, mismatched = Certificate.from_pem(text)
    except (pem.PemError, ValueError) as exc:
        print(red(f"✗ certificat illisible : {exc}"))
        return 2

    try:
        ra = ra_mod.ra_load(_ra_dir(args))
    except FileNotFoundError:
        ra = None
    result = ra_mod.ra_verify(cert, ra, mismatched)

    # --- partie publique, sans mot de passe ---
    print(bold("┌─ informations publiques"), dim(f"— {path.name}"))
    s = cert.subject
    for label, value in [
        ("nom", s.name), ("email", s.email), ("fonction", s.role),
        ("organisation", s.organization), ("serie", cert.serial),
        ("suite", cert.suite),
        ("validite", f"{cert.not_before[:10]} → {cert.not_after[:10]}"),
        ("emis par", f"{cert.issuer} ({cert.issuer_fingerprint()})"),
        ("empreinte", cert.fingerprint()),
        ("pk_sd", cert.pk_sd.hex()),
        ("pk_rcv", cert.pk_rcv.hex()),
    ]:
        print(f"│  {label:13s} {value}")
    line = (f"│  {'controles':13s} signature RA {mark(result.signature_ok)}   "
            f"periode {mark(result.period_ok)}")
    if result.issuer_matches is not None:
        line += f"   RA local {mark(result.issuer_matches)}"
    line += f"   en-tetes {mark(result.headers_ok)}"
    print(line)
    for problem in result.problems:
        print(red(f"│  ! {problem}"))

    # --- partie masquee ---
    if not pem.has_block(text, ra_mod.KEY_TAG):
        print(bold("└─ aucune partie masquee"),
              dim("— certificat public seul, sans cle privee"))
        return 0 if result.valid else 1

    print(bold("├─ informations masquees"), dim("— mot de passe requis"))
    if args.public:
        print(dim("│  (ignorees : --public demande)"))
        print(bold("└─"))
        return 0 if result.valid else 1

    try:
        account = keystore.load(path)
    except (ValueError, pem.PemError) as exc:
        print(red(f"│  ✗ {exc}"))
        return 2
    try:
        unlocked = _unlock(account)
    except vault.BadPassword as exc:
        print(red(f"│  ✗ {exc}"))
        print(bold("└─"))
        return 2

    if unlocked.private:
        for key, value in unlocked.private.items():
            print(f"│  {key:13s} {cyan(str(value))}")
    else:
        print(dim("│  aucune donnee personnelle privee enregistree"))
    print(f"│  {'sk_sd':13s} {_mask(unlocked.sk_sd, args.reveal)}")
    print(f"│  {'sk_rcv':13s} {_mask(unlocked.sk_rcv, args.reveal)}")
    print(bold("└─ ouvert"))
    if args.reveal:
        print()
        print(red("  Les cles privees sont affichees en clair ci-dessus."))
        print(red("  Efface ton terminal si quelqu'un peut le lire."))
    return 0 if result.valid else 1


# --- signature et verification ----------------------------------------------


def cmd_sign(args) -> int:
    try:
        account = _pick(args)
    except (FileNotFoundError, ValueError) as exc:
        print(red(f"✗ {exc}"))
        return 2
    print(dim(f"  signataire : {account.subject.name} <{account.subject.email}>"))
    print(dim(f"  certificat : {account.path.name}"))
    print()
    title = ask_optional("Titre du document", args.title)
    reference = ask_optional("Numero d'ordre", args.ref)
    print()
    try:
        unlocked = _unlock(account)
    except vault.BadPassword as exc:
        print(red(f"✗ {exc}"))
        return 2

    banner.entete("signer")
    banner.etapes("signer")
    cert = unlocked.cert
    doc = Path(args.file)
    # En mode --pdf, on ne signe que le PDF tel qu'il est aujourd'hui : le
    # QR sera ajoute apres, en mise a jour incrementale, sans toucher a
    # ces octets.
    document = doc.read_bytes()
    meta = Metadata.now(
        filename=doc.name,
        signer=cert.subject.name,
        title=title,
        reference=reference,
    )
    m = build_message(meta, document)
    C = sc(unlocked.dp, unlocked.sk_sd, cert.pk_rcv, m)
    nr = nr_generate(unlocked.dp, unlocked.sk_rcv, cert.pk_sd, C)
    if nr is None:  # pragma: no cover
        print(red("✗ erreur interne : le chiffre produit echoue a Usc"))
        return 1

    ev = Evidence(
        dp=unlocked.dp, meta=meta, pk_sd=cert.pk_sd, pk_rcv=cert.pk_rcv,
        c1=C.c1, sigma=C.sigma, t=C.t, nr=nr,
    )
    if args.pdf:
        return _finish_pdf(args, doc, document, ev, cert, meta)

    payload = ev.to_bytes()
    out = Path(args.out) if args.out else doc.with_suffix(doc.suffix + ".qr.png")
    try:
        info = qr.write(payload, out, scale=args.scale)
        print(green("✓ signe"), dim(f"{doc.name} · {len(document)} octets"))
        print(f"  preuve       {out}")
        print(f"  qr           version {info['version']}-{info['error']} · "
              f"{info['bytes']} octets")
    except qr.QRTooLarge as exc:
        stem = out.name[:-4] if out.name.endswith(".png") else out.name
        if stem.endswith(".qr"):
            stem = stem[:-3]
        out = out.parent / (stem + ".snr")
        out.write_text(qr.encode_payload(payload))
        print(green("✓ signe"), dim(f"{doc.name} · {len(document)} octets"))
        print(f"  preuve       {out}")
        print(dim(f"  note         {exc} ; fichier annexe ecrit"))

    if meta.title:
        print(f"  titre        {meta.title}")
    if meta.reference:
        print(f"  numero       {meta.reference}")
    print(f"  signataire   {cert.subject.name} <{cert.subject.email}>")
    print(f"  certificat   {cert.serial}")
    print(f"  date         {meta.timestamp}")
    print()
    print(dim("  La preuve contient tau1 : qui la detient peut dechiffrer ce"))
    print(dim("  document. Ne la publie que pour un document public."))
    return 0


def _finish_pdf(args, doc: Path, document: bytes, ev: Evidence, cert, meta) -> int:
    """Incruste la preuve dans le PDF, sans alterer les octets signes."""
    ev = Evidence(**{**ev.__dict__, "prefix_len": len(document)})
    out = Path(args.out) if args.out else doc.with_name(f"{doc.stem}-signe.pdf")
    try:
        info = pdfsign.embed_qr(
            doc, qr.encode_payload(ev.to_bytes()), out,
            page=args.page - 1, position=args.position,
            margin=args.margin, size=args.qr_size,
        )
    except pdfsign.PdfSignError as exc:
        print(red(f"✗ {exc}"))
        return 2

    print(green("✓ signe"), dim(f"{doc.name} · {len(document)} octets"))
    print(f"  document     {out}")
    print(f"  qr           page {info['page']}/{info['pages']} · "
          f"{info['position']} · {int(info['box'][2])} pt")
    print(f"  signe        {info['prefix_len']} octets sur {info['total']} "
          f"(+{info['added']} pour le QR)")
    if meta.title:
        print(f"  titre        {meta.title}")
    if meta.reference:
        print(f"  numero       {meta.reference}")
    print(f"  signataire   {cert.subject.name} <{cert.subject.email}>")
    print(f"  certificat   {cert.serial}")
    print(f"  date         {meta.timestamp}")
    print()
    print(dim("  Le PDF d'origine est intact : le QR est ajoute apres ses"))
    print(dim("  octets, en mise a jour incrementale. Verifie avec :"))
    print(dim(f"    sn verify {out} --pdf"))
    return 0


def _load_evidence(args) -> Evidence:
    sources = [args.qr, args.snr, args.payload]
    if sum(x is not None for x in sources) != 1:
        raise SystemExit("donne exactement une source : --qr, --snr ou --payload")
    if args.qr:
        blob = qr.read(Path(args.qr))
    elif args.snr:
        blob = qr.decode_payload(Path(args.snr).read_text())
    else:
        blob = qr.decode_payload(args.payload)
    return Evidence.from_bytes(blob)


def cmd_verify(args) -> int:
    path = Path(args.file)
    extracted: Path | None = None
    tail: tuple[bool, str] | None = None
    visual: tuple[bool, str] | None = None
    objects: tuple[bool, str] | None = None
    if args.pdf:
        try:
            ev = Evidence.from_bytes(pdfsign.extract_payload(path))
            if ev.prefix_len == 0:
                raise pdfsign.PdfSignError(
                    "cette preuve a ete emise pour un fichier hors PDF "
                    "(aucun prefixe signe) : elle ne peut pas couvrir ce PDF"
                )
            document = pdfsign.signed_prefix(path, ev.prefix_len)
        except (pdfsign.PdfSignError, ValueError) as exc:
            print(red(f"✗ {exc}"))
            return 2
        # Les octets d'apres ne sont pas signes. On ne peut pas les
        # authentifier, mais on sait ce qu'ils ont le droit de contenir :
        # une seule revision, qui ne change le rendu que la ou est le QR
        # et n'introduit aucun objet actif.
        tail = pdfsign.check_tail(path, ev.prefix_len)
        try:
            visual = pdfcheck.check_visual(path, ev.prefix_len)
            objects = pdfcheck.check_objects(path, ev.prefix_len)
        except pdfcheck.CheckError as exc:
            print(red(f"✗ {exc}"))
            return 2
        # Seuls ces octets sont signes : on les met de cote pour que le
        # lecteur puisse voir ce qui a reellement ete signe, plutot que
        # de faire confiance a l'affichage du fichier recu.
        extracted = path.with_name(f"{path.stem}-verifie.pdf")
        extracted.write_bytes(document)
    else:
        document = path.read_bytes()
        try:
            ev = _load_evidence(args)
        except (ValueError, RuntimeError) as exc:
            print(red(f"✗ preuve illisible : {exc}"))
            return 2

    banner.entete("verifier")
    banner.etapes("verifier")
    checks = ev.checks(document)
    doc_ok = all(checks.values())

    # Si un certificat est fourni, on relie pk_sd a une identite certifiee.
    identity = None
    if args.cert:
        try:
            ra = ra_mod.ra_load(_ra_dir(args))
        except FileNotFoundError:
            ra = None
        try:
            cert, result = ra_mod.ra_verify_file(Path(args.cert), ra)
        except (pem.PemError, ValueError) as exc:
            print(red(f"✗ certificat illisible : {exc}"))
            return 2
        identity = (cert, result, cert.pk_sd == ev.pk_sd)

    pdf_checks = [c for c in (tail, visual, objects) if c is not None]
    pdf_ok = all(c[0] for c in pdf_checks)
    overall = (
        doc_ok
        and pdf_ok
        and (identity is None or (identity[1].valid and identity[2]))
    )
    print(green(bold("✓ DOCUMENT AUTHENTIQUE")) if overall
          else red(bold("✗ DOCUMENT NON AUTHENTIQUE")))

    if identity:
        cert, result, bound = identity
        s = cert.subject
        print(f"  signataire   {s.name} <{s.email}>")
        print(f"  fonction     {s.role} · {s.organization}")
        print(f"  certificat   {cert.serial} ({cert.issuer})")
    else:
        print(f"  signataire   {ev.meta.signer}  "
              f"{_fp(ev.pk_sd, ev.dp.suite.sig.name)}")
        print(dim("               (nom declare, non certifie : passe --cert)"))
    if ev.meta.title:
        print(f"  titre        {bold(ev.meta.title)}")
    if ev.meta.reference:
        print(f"  numero       {ev.meta.reference}")
    print(f"  date         {ev.meta.timestamp}")
    print(f"  document     {ev.meta.filename} · {len(document)} octets")
    if extracted is not None:
        total = path.stat().st_size
        print(f"  signe        {len(document)} octets sur {total} "
              f"(+{total - len(document)} ajoutes apres signature)")
        print(f"  verifie      {bold(str(extracted))}")
    print(f"  controles    signature {mark(checks['signature'])}   "
          f"tag MAC {mark(checks['mac_tag'])}", end="")
    if tail is not None:
        print(f"   revisions {mark(tail[0])}   visuel {mark(visual[0])}"
              f"   objets {mark(objects[0])}", end="")
    if identity:
        cert, result, bound = identity
        print(f"   certificat {mark(result.valid)}   "
              f"cle liee {mark(bound)}")
        for problem in result.problems:
            print(red(f"  ! {problem}"))
        if not bound:
            print(red("  ! la cle du certificat ne signe pas ce document"))
    else:
        print()

    if pdf_checks and not pdf_ok:
        print()
        for ok, detail in pdf_checks:
            if not ok:
                print(red(f"  ! {detail}"))
        print(red("  Du contenu a ete ajoute apres la signature ; les octets"))
        print(red(f"  signes sont dans {extracted.name}."))
    elif overall and extracted is not None:
        print()
        print(dim(f"  {tail[1]}, rendu et objets conformes. Les octets signes"))
        print(dim(f"  sont dans {extracted.name}."))
    if not doc_ok:
        print()
        print(red("  le document ne correspond pas a cette preuve"))
        if ev.meta.filename != Path(args.file).name:
            print(dim(f"  indice       preuve emise pour '{ev.meta.filename}', "
                      f"tu as passe '{Path(args.file).name}'"))
    return 0 if overall else 1


def _recipient(args) -> Certificate:
    """Le certificat du destinataire, controle aupres du RA."""
    try:
        ra = ra_mod.ra_load(_ra_dir(args))
    except FileNotFoundError:
        ra = None
    cert, result = ra_mod.ra_verify_file(Path(args.to), ra)
    if not result.valid:
        for problem in result.problems:
            print(red(f"  ! {problem}"))
        raise SystemExit("certificat du destinataire refuse")
    return cert


def cmd_encrypt(args) -> int:
    """Signcrypte un fichier pour un destinataire precis."""
    try:
        account = _pick(args)
        recipient = _recipient(args)
    except (FileNotFoundError, ValueError, pem.PemError) as exc:
        print(red(f"✗ {exc}"))
        return 2

    if recipient.tau0 != account.cert.tau0:
        print(red("✗ le destinataire releve d'un autre RA : domaines "
                  "incompatibles"))
        return 2
    if recipient.suite != account.cert.suite:
        print(red(f"✗ suites differentes : {account.cert.suite} contre "
                  f"{recipient.suite}"))
        return 2

    print(dim(f"  expediteur   {account.subject.name} <{account.subject.email}>"))
    print(dim(f"  destinataire {recipient.subject.name} <{recipient.subject.email}>"))
    print()
    title = ask_optional("Titre du document", args.title)
    reference = ask_optional("Numero d'ordre", args.ref)
    print()
    try:
        unlocked = _unlock(account)
    except vault.BadPassword as exc:
        print(red(f"✗ {exc}"))
        return 2

    banner.entete("chiffrer")
    banner.etapes("chiffrer")
    doc = Path(args.file)
    document = doc.read_bytes()
    meta = Metadata.now(doc.name, account.subject.name, title, reference)
    C = sc(unlocked.dp, unlocked.sk_sd, recipient.pk_rcv,
           build_message(meta, document))
    sealed = Sealed(dp=unlocked.dp, meta=meta, pk_sd=account.pk_sd,
                    pk_rcv=recipient.pk_rcv, C=C)

    out = Path(args.out) if args.out else doc.with_suffix(doc.suffix + ".snc")
    out.write_bytes(sealed.to_bytes())
    print(green("✓ chiffre et signe"), dim(f"{doc.name} · {len(document)} octets"))
    print(f"  fichier      {out} ({out.stat().st_size} octets)")
    print(f"  pour         {recipient.subject.name} <{recipient.subject.email}>")
    print(f"  signe par    {account.subject.name}")
    if title:
        print(f"  titre        {title}")
    print()
    print(dim("  Seul le destinataire peut l'ouvrir. Le document n'apparait"))
    print(dim("  nulle part en clair dans ce fichier."))
    return 0


def cmd_decrypt(args) -> int:
    """Ouvre un .snc : rend le document et nomme son expediteur."""
    try:
        account = _pick(args)
    except (FileNotFoundError, ValueError) as exc:
        print(red(f"✗ {exc}"))
        return 2
    try:
        sealed = Sealed.from_bytes(Path(args.file).read_bytes())
    except ValueError as exc:
        print(red(f"✗ {exc}"))
        return 2

    if sealed.pk_rcv != account.pk_rcv:
        print(red("✗ ce fichier n'a pas ete chiffre pour ce compte"))
        return 1
    print(dim(f"  destinataire {account.subject.name} <{account.subject.email}>"))
    try:
        unlocked = _unlock(account)
    except vault.BadPassword as exc:
        print(red(f"✗ {exc}"))
        return 2

    banner.entete("dechiffrer")
    banner.etapes("dechiffrer")
    document = sealed.open(unlocked.sk_rcv)
    if document is None:
        print(red("✗ CONTENU REFUSE"))
        print(red("  la signature ou le tag ne correspondent pas : le fichier"))
        print(red("  a ete altere, ou ne vient pas de qui il pretend"))
        return 1

    out = Path(args.out) if args.out else Path(sealed.meta.filename)
    out.write_bytes(document)
    print(green("✓ OUVERT ET AUTHENTIFIE"))
    print(f"  document     {out} ({len(document)} octets)")
    print(f"  expediteur   {sealed.meta.signer}  "
          f"{_fp(sealed.pk_sd, sealed.dp.suite.sig.name)}")
    if sealed.meta.title:
        print(f"  titre        {sealed.meta.title}")
    if sealed.meta.reference:
        print(f"  numero       {sealed.meta.reference}")
    print(f"  date         {sealed.meta.timestamp}")

    if args.proof:
        nr = sealed.evidence(unlocked.sk_rcv)
        Path(args.proof).write_text(qr.encode_payload(nr.to_bytes()))
        print(f"  preuve       {args.proof}")
        print()
        print(dim("  Cette preuve permet a un tiers d'etablir que l'expediteur"))
        print(dim("  a bien envoye ce document, sans son accord. Elle revele"))
        print(dim("  aussi son contenu."))
    return 0


def cmd_arbitrate(args) -> int:
    """PV : un tiers etablit l'origine d'un document, sans aucun secret."""
    try:
        sealed = Sealed.from_bytes(Path(args.file).read_bytes())
        nr = Keys.from_bytes(qr.decode_payload(Path(args.proof).read_text()))
    except ValueError as exc:
        print(red(f"✗ {exc}"))
        return 2

    document = Path(args.document).read_bytes()
    ok = sealed.check(document, nr)

    identity = None
    if args.cert:
        try:
            ra = ra_mod.ra_load(_ra_dir(args))
        except FileNotFoundError:
            ra = None
        try:
            cert, result = ra_mod.ra_verify_file(Path(args.cert), ra)
        except (pem.PemError, ValueError) as exc:
            print(red(f"✗ certificat illisible : {exc}"))
            return 2
        identity = (cert, result, cert.pk_sd == sealed.pk_sd)
        ok = ok and result.valid and identity[2]

    print(green(bold("✓ ORIGINE ETABLIE")) if ok
          else red(bold("✗ ORIGINE NON ETABLIE")))
    if identity:
        cert, result, bound = identity
        print(f"  expediteur   {cert.subject.name} <{cert.subject.email}>")
        print(f"  fonction     {cert.subject.role} · {cert.subject.organization}")
        print(f"  certificat   {cert.serial} ({cert.issuer})  "
              f"{mark(result.valid)}   cle liee {mark(bound)}")
    else:
        print(f"  expediteur   {sealed.meta.signer}  "
              f"{_fp(sealed.pk_sd, sealed.dp.suite.sig.name)}")
        print(dim("               (non certifie : passe --cert)"))
    print(f"  document     {args.document} · {len(document)} octets")
    if sealed.meta.title:
        print(f"  titre        {sealed.meta.title}")
    print(f"  date         {sealed.meta.timestamp}")
    if not ok:
        print()
        print(red("  ce document ne correspond pas a ce fichier scelle"))
    return 0 if ok else 1


def cmd_inspect(args) -> int:
    try:
        ev = _load_evidence(args)
    except (ValueError, RuntimeError) as exc:
        print(red(f"✗ preuve illisible : {exc}"))
        return 2
    s = ev.dp.suite
    print(bold("enregistrement de preuve"))
    for k, v in [
        ("suite", f"{s.name} ({s.sig.name} + {s.kem.name} + {s.sym.name})"),
        ("signataire", ev.meta.signer),
        ("titre", ev.meta.title or dim("(aucun)")),
        ("numero", ev.meta.reference or dim("(aucun)")),
        ("fichier", ev.meta.filename),
        ("date", ev.meta.timestamp),
        ("tau0", ev.dp.tau0.hex()),
        ("pk_sd", ev.pk_sd.hex()),
        ("pk_rcv", ev.pk_rcv.hex()),
        ("c1", f"{ev.c1.hex()[:48]}… ({len(ev.c1)} o)"),
        ("sigma", f"{ev.sigma.hex()[:48]}… ({len(ev.sigma)} o)"),
        ("t", ev.t.hex()),
        ("nr.tau1", ev.nr.t1.hex()),
        ("nr.tau1'", ev.nr.t1p.hex()),
        ("nr.tau2", ev.nr.t2.hex()),
        ("nr.tau2'", ev.nr.t2p.hex()),
        ("taille", f"{len(ev.to_bytes())} octets"),
    ]:
        print(f"  {k:11s} {v}")
    return 0


# --- parseur ----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sn",
        description="Signature de documents avec le schema SN (Togde & Sarr), "
                    "certificats PEM emis par une autorite d'enregistrement.",
    )
    p.add_argument("--register", help="dossier des comptes (defaut register-key/)")
    p.add_argument("--ra-home", help="dossier du RA (defaut .ra/)")
    p.add_argument("--no-banner", action="store_true",
                   help="supprimer la banniere et les animations")
    sub = p.add_subparsers(dest="command", required=True)

    ra = sub.add_parser("ra", help="autorite d'enregistrement")
    rasub = ra.add_subparsers(dest="ra_command", required=True)
    ri = rasub.add_parser("init", help="creer le RA (une seule fois)")
    ri.add_argument("--name", default="SN Register Authority")
    ri.add_argument("--suite", default="classical", choices=["classical", "pq"])
    ri.set_defaults(func=cmd_ra_init)
    rs = rasub.add_parser("show", help="afficher le RA")
    rs.set_defaults(func=cmd_ra_show)
    rv = rasub.add_parser("verify", help="RA-verify : controler un certificat")
    rv.add_argument("certificate", help="fichier .pem")
    rv.set_defaults(func=cmd_ra_verify)

    i = sub.add_parser("init", help="creer un compte certifie")
    i.add_argument("--name")
    i.add_argument("--email")
    i.add_argument("--role", help="fonction")
    i.add_argument("--org", help="organisation")
    i.add_argument("--suite", default="classical", choices=["classical", "pq"])
    i.add_argument("--telephone", help="telephone (prive)")
    i.add_argument("--adresse", help="adresse (privee)")
    i.add_argument("--cni", help="numero CNI ou passeport (prive)")
    i.add_argument("--private", action="append", metavar="CLE=VALEUR",
                   help="autre donnee privee (repetable)")
    i.set_defaults(func=cmd_init)

    a = sub.add_parser("account", help="gerer ses comptes")
    asub = a.add_subparsers(dest="account_command", required=True)
    al = asub.add_parser("list", help="lister les comptes du registre")
    al.set_defaults(func=cmd_account_list)
    ash = asub.add_parser("show", help="detailler un compte")
    ash.add_argument("--cert", help="fichier .pem du compte")
    ash.set_defaults(func=cmd_account_show)
    ax = asub.add_parser("export", help="exporter le certificat public seul")
    ax.add_argument("--cert", help="fichier .pem du compte")
    ax.add_argument("-o", "--out")
    ax.set_defaults(func=cmd_cert_export)

    s = sub.add_parser("sign", help="signer un fichier (demande le mot de passe)")
    s.add_argument("file")
    s.add_argument("--cert", help="fichier .pem du compte signataire")
    s.add_argument("--pdf", action="store_true",
                   help="incruster le QR dans le PDF (mise a jour incrementale)")
    s.add_argument("--page", type=int, default=1, help="page du QR (defaut 1)")
    s.add_argument("--position", default=pdfsign.DEFAULT_POSITION,
                   choices=list(pdfsign.POSITIONS),
                   help="coin du QR (defaut bottom-right)")
    s.add_argument("--margin", type=float, default=pdfsign.DEFAULT_MARGIN,
                   help="marge en points (defaut 10)")
    s.add_argument("--qr-size", type=float, default=pdfsign.DEFAULT_SIZE,
                   dest="qr_size", help="cote du QR en points (defaut 100)")
    s.add_argument("--title", help="titre du document")
    s.add_argument("--ref", help="numero d'ordre (facultatif)")
    s.add_argument("-o", "--out")
    s.add_argument("--scale", type=int, default=8)
    s.set_defaults(func=cmd_sign)

    e = sub.add_parser("encrypt", help="chiffrer et signer pour un destinataire")
    e.add_argument("file")
    e.add_argument("--to", required=True, help="certificat .pem du destinataire")
    e.add_argument("--cert", help="fichier .pem du compte expediteur")
    e.add_argument("--title", help="titre du document")
    e.add_argument("--ref", help="numero d'ordre (facultatif)")
    e.add_argument("-o", "--out")
    e.set_defaults(func=cmd_encrypt)

    d = sub.add_parser("decrypt", help="ouvrir un .snc qui vous est destine")
    d.add_argument("file")
    d.add_argument("--cert", help="fichier .pem du compte destinataire")
    d.add_argument("--proof", help="ecrire la preuve de non-repudiation")
    d.add_argument("-o", "--out")
    d.set_defaults(func=cmd_decrypt)

    ar = sub.add_parser("arbitrate", help="etablir l'origine d'un document (PV)")
    ar.add_argument("file", help="fichier .snc")
    ar.add_argument("--document", required=True, help="le document presume")
    ar.add_argument("--proof", required=True, help="preuve remise par le destinataire")
    ar.add_argument("--cert", help="certificat .pem de l'expediteur presume")
    ar.set_defaults(func=cmd_arbitrate)

    v = sub.add_parser("verify", help="verifier un fichier (aucun mot de passe)")
    v.add_argument("file")
    v.add_argument("--qr")
    v.add_argument("--snr")
    v.add_argument("--payload")
    v.add_argument("--pdf", action="store_true",
                   help="lire la preuve dans le PDF lui-meme")
    v.add_argument("--cert", help="certificat .pem du signataire presume")
    v.set_defaults(func=cmd_verify)

    o = sub.add_parser("open", help="ouvrir un certificat .pem")
    o.add_argument("certificate", help="fichier .pem")
    o.add_argument("--reveal", action="store_true",
                   help="afficher les cles privees en entier")
    o.add_argument("--public", action="store_true",
                   help="s'arreter a la partie publique, sans mot de passe")
    o.set_defaults(func=cmd_open)

    n_ = sub.add_parser("inspect", help="detailler une preuve")
    n_.add_argument("--qr")
    n_.add_argument("--snr")
    n_.add_argument("--payload")
    n_.set_defaults(func=cmd_inspect)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "no_banner", False):
        banner.ACTIF = False
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(red(f"✗ {exc}"))
        return 2
    except (KeyboardInterrupt, EOFError):
        print()
        print(dim("annule"))
        return 130


if __name__ == "__main__":
    sys.exit(main())
