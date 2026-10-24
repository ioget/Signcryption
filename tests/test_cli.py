"""Flux complets en ligne de commande."""

from pathlib import Path

import pytest

from sn.cli import main

PW_R = "Mot2Passe!rosly"
PW_F = "Autre!Passe99"


def run(*argv) -> int:
    return main([str(a) for a in argv])


@pytest.fixture
def ra_home(tmp_path):
    d = tmp_path / "ra"
    assert run("--ra-home", d, "ra", "init", "--name", "Test RA") == 0
    return d


@pytest.fixture
def reg(tmp_path):
    return tmp_path / "register-key"


@pytest.fixture
def rosly(ra_home, reg, monkeypatch, capsys):
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    assert run(
        "--ra-home", ra_home, "--register", reg, "init",
        "--name", "Rosly Mamakem", "--email", "rosly@ugb.sn",
        "--role", "Chercheur", "--org", "AIMS / UGB",
    ) == 0
    capsys.readouterr()
    from sn import keystore
    return keystore.discover(reg)[0]


@pytest.fixture
def doc(tmp_path):
    p = tmp_path / "contrat.txt"
    p.write_text("Rosly doit 500 EUR a Fatou.\n")
    return p


def add_account(ra_home, reg, name, email, password, monkeypatch, capsys):
    monkeypatch.setenv("SN_PASSWORD", password)
    run("--ra-home", ra_home, "--register", reg, "init",
        "--name", name, "--email", email, "--role", "R", "--org", "UGB")
    capsys.readouterr()


# --- creation de comptes ----------------------------------------------------


def test_init_needs_a_ra(tmp_path, reg, monkeypatch, capsys):
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    code = run("--ra-home", tmp_path / "nope", "--register", reg, "init",
               "--name", "X", "--email", "x@y.sn", "--role", "R", "--org", "O")
    assert code == 2 and "ra init" in capsys.readouterr().out


def test_init_can_be_run_several_times(ra_home, reg, monkeypatch, capsys):
    """Le bug signale : creer un deuxieme compte ne doit pas etre refuse."""
    add_account(ra_home, reg, "Rosly Mamakem", "rosly@ugb.sn", PW_R, monkeypatch, capsys)
    add_account(ra_home, reg, "Fatou Ndiaye", "fatou@ugb.sn", PW_F, monkeypatch, capsys)
    assert run("--ra-home", ra_home, "--register", reg, "account", "list") == 0
    out = capsys.readouterr().out
    assert "2 compte(s)" in out and "Rosly" in out and "Fatou" in out


def test_account_file_is_a_pem_with_readable_identity(rosly):
    text = rosly.read_text()
    assert text.startswith("-----BEGIN SN CERTIFICATE-----")
    assert "Name: Rosly Mamakem" in text
    assert "Email: rosly@ugb.sn" in text
    assert "-----BEGIN SN ENCRYPTED PRIVATE KEY-----" in text


def test_private_keys_are_encrypted(rosly):
    import re
    assert not re.search(r"\bsk_(sd|rcv)\b", rosly.read_text())


# --- RA-verify --------------------------------------------------------------


def test_ra_verify_accepts_a_real_certificate(ra_home, rosly, capsys):
    assert run("--ra-home", ra_home, "ra", "verify", rosly) == 0
    out = capsys.readouterr().out
    assert "IDENTITE CERTIFIEE" in out
    assert "Rosly Mamakem" in out and "rosly@ugb.sn" in out
    assert "signature RA ✓" in out and "RA local ✓" in out


def test_ra_verify_rejects_a_faked_header(ra_home, rosly, tmp_path, capsys):
    faked = tmp_path / "faux.pem"
    faked.write_text(
        rosly.read_text().replace("Name: Rosly Mamakem", "Name: Pirate")
    )
    assert run("--ra-home", ra_home, "ra", "verify", faked) == 1
    out = capsys.readouterr().out
    assert "NON VALIDE" in out and "en-tetes lisibles falsifies" in out
    assert "Rosly Mamakem" in out  # le corps signe dit la verite


def test_ra_verify_rejects_another_ras_certificate(
    tmp_path, ra_home, reg, monkeypatch, capsys
):
    other_ra, other_reg = tmp_path / "ra2", tmp_path / "reg2"
    run("--ra-home", other_ra, "ra", "init", "--name", "Autre RA")
    monkeypatch.setenv("SN_PASSWORD", PW_F)
    run("--ra-home", other_ra, "--register", other_reg, "init",
        "--name", "Etranger", "--email", "e@x.sn", "--role", "R", "--org", "O")
    capsys.readouterr()
    from sn import keystore
    foreign = keystore.discover(other_reg)[0]
    assert run("--ra-home", ra_home, "ra", "verify", foreign) == 1
    assert "autre RA" in capsys.readouterr().out


def test_exported_certificate_carries_no_private_key(ra_home, reg, rosly, tmp_path, capsys):
    out = tmp_path / "public.pem"
    assert run("--register", reg, "account", "export", "-o", out) == 0
    assert "PRIVATE" not in out.read_text()
    assert run("--ra-home", ra_home, "ra", "verify", out) == 0


# --- signature --------------------------------------------------------------


def test_sign_and_verify(ra_home, reg, rosly, doc, tmp_path, capsys):
    png = tmp_path / "ev.png"
    assert run("--register", reg, "sign", doc, "-o", png) == 0
    capsys.readouterr()
    assert run("--register", reg, "verify", doc, "--qr", png) == 0
    assert "AUTHENTIQUE" in capsys.readouterr().out


def test_sign_asks_which_account_when_several(
    ra_home, reg, doc, tmp_path, monkeypatch, capsys
):
    add_account(ra_home, reg, "Rosly Mamakem", "rosly@ugb.sn", PW_R, monkeypatch, capsys)
    add_account(ra_home, reg, "Fatou Ndiaye", "fatou@ugb.sn", PW_F, monkeypatch, capsys)
    assert run("--register", reg, "sign", doc, "-o", tmp_path / "e.png") == 2
    out = capsys.readouterr().out
    assert "2 comptes disponibles" in out and "--cert" in out


def test_sign_selects_by_certificate(ra_home, reg, doc, tmp_path, monkeypatch, capsys):
    add_account(ra_home, reg, "Rosly Mamakem", "rosly@ugb.sn", PW_R, monkeypatch, capsys)
    add_account(ra_home, reg, "Fatou Ndiaye", "fatou@ugb.sn", PW_F, monkeypatch, capsys)
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    from sn import keystore
    rosly_pem = next(p for p in keystore.discover(reg) if "rosly" in p.name)
    png = tmp_path / "ev.png"
    assert run("--register", reg, "sign", doc, "--cert", rosly_pem, "-o", png) == 0
    assert "Rosly Mamakem" in capsys.readouterr().out


def test_sign_requires_the_right_password(
    reg, rosly, doc, tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("SN_PASSWORD", "pas-le-bon")
    assert run("--register", reg, "sign", doc, "-o", tmp_path / "e.png") == 2
    assert "mot de passe incorrect" in capsys.readouterr().out


def test_verify_needs_no_password(reg, rosly, doc, tmp_path, monkeypatch, capsys):
    png = tmp_path / "ev.png"
    run("--register", reg, "sign", doc, "-o", png)
    capsys.readouterr()
    monkeypatch.delenv("SN_PASSWORD", raising=False)
    assert run("--register", reg, "verify", doc, "--qr", png) == 0


# --- verification liee au certificat ----------------------------------------


def test_verify_with_certificate_shows_certified_identity(
    ra_home, reg, rosly, doc, tmp_path, capsys
):
    png = tmp_path / "ev.png"
    run("--register", reg, "sign", doc, "-o", png)
    capsys.readouterr()
    assert run("--ra-home", ra_home, "--register", reg, "verify", doc,
               "--qr", png, "--cert", rosly) == 0
    out = capsys.readouterr().out
    assert "AUTHENTIQUE" in out
    assert "rosly@ugb.sn" in out and "Chercheur" in out
    assert "certificat ✓" in out and "cle liee ✓" in out


def test_verify_rejects_someone_elses_certificate(
    ra_home, reg, doc, tmp_path, monkeypatch, capsys
):
    add_account(ra_home, reg, "Rosly Mamakem", "rosly@ugb.sn", PW_R, monkeypatch, capsys)
    add_account(ra_home, reg, "Fatou Ndiaye", "fatou@ugb.sn", PW_F, monkeypatch, capsys)
    from sn import keystore
    accounts = {a.subject.email: a.path for a in map(keystore.load, keystore.discover(reg))}
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    png = tmp_path / "ev.png"
    run("--register", reg, "sign", doc, "--cert", accounts["rosly@ugb.sn"], "-o", png)
    capsys.readouterr()
    fatou_public = tmp_path / "fatou.pem"
    run("--register", reg, "account", "export", "--cert", accounts["fatou@ugb.sn"],
        "-o", fatou_public)
    capsys.readouterr()
    assert run("--ra-home", ra_home, "--register", reg, "verify", doc,
               "--qr", png, "--cert", fatou_public) == 1
    out = capsys.readouterr().out
    assert "cle liee ✗" in out and "ne signe pas ce document" in out


def test_verify_without_certificate_says_the_name_is_unverified(
    reg, rosly, doc, tmp_path, capsys
):
    png = tmp_path / "ev.png"
    run("--register", reg, "sign", doc, "-o", png)
    capsys.readouterr()
    run("--register", reg, "verify", doc, "--qr", png)
    assert "non certifie" in capsys.readouterr().out


# --- detection des modifications --------------------------------------------


def test_modified_document_is_rejected(reg, rosly, doc, tmp_path, capsys):
    png = tmp_path / "ev.png"
    run("--register", reg, "sign", doc, "-o", png)
    capsys.readouterr()
    doc.write_text("Rosly doit 900 EUR a Fatou.\n")
    assert run("--register", reg, "verify", doc, "--qr", png) == 1
    assert "NON AUTHENTIQUE" in capsys.readouterr().out


def test_evidence_from_another_document_is_rejected(reg, rosly, tmp_path, capsys):
    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("document A"); b.write_text("document B")
    png = tmp_path / "a.png"
    run("--register", reg, "sign", a, "-o", png)
    capsys.readouterr()
    assert run("--register", reg, "verify", b, "--qr", png) == 1
    assert "'a.txt'" in capsys.readouterr().out


# --- divers -----------------------------------------------------------------


def test_pq_account_writes_a_sidecar(ra_home, reg, doc, monkeypatch, capsys):
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    run("--ra-home", ra_home, "--register", reg, "init", "--suite", "pq",
        "--name", "Rosly", "--email", "r@ugb.sn", "--role", "R", "--org", "UGB")
    capsys.readouterr()
    assert run("--register", reg, "sign", doc) == 0
    assert "annexe" in capsys.readouterr().out
    snr = doc.parent / (doc.name + ".snr")
    assert snr.exists()
    assert run("--register", reg, "verify", doc, "--snr", snr) == 0


def test_account_show(ra_home, reg, rosly, capsys):
    assert run("--ra-home", ra_home, "--register", reg, "account", "show") == 0
    out = capsys.readouterr().out
    assert "Rosly Mamakem" in out and "rosly@ugb.sn" in out


def test_account_list_on_empty_register(reg, capsys):
    assert run("--register", reg, "account", "list") == 0
    assert "aucun compte" in capsys.readouterr().out


def test_inspect(reg, rosly, doc, tmp_path, capsys):
    png = tmp_path / "ev.png"
    run("--register", reg, "sign", doc, "-o", png)
    capsys.readouterr()
    assert run("--register", reg, "inspect", "--qr", png) == 0
    out = capsys.readouterr().out
    assert all(f in out for f in ("suite", "tau0", "pk_sd", "nr.tau1"))


def test_verify_requires_exactly_one_source(reg, rosly, doc):
    with pytest.raises(SystemExit):
        run("--register", reg, "verify", doc)


# --- ouverture d'un certificat ----------------------------------------------


@pytest.fixture
def with_private(ra_home, reg, monkeypatch, capsys):
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    run("--ra-home", ra_home, "--register", reg, "init",
        "--name", "Amadou Ba", "--email", "amadou@ugb.sn",
        "--role", "Enseignant", "--org", "UGB",
        "--private", "telephone=+221 77 123 45 67",
        "--private", "CNI=1234567890123")
    capsys.readouterr()
    from sn import keystore
    return keystore.discover(reg)[0]


def test_open_shows_public_part_then_private(ra_home, with_private, capsys):
    assert run("--ra-home", ra_home, "open", with_private) == 0
    out = capsys.readouterr().out
    assert "informations publiques" in out and "informations masquees" in out
    assert "Amadou Ba" in out and "amadou@ugb.sn" in out
    assert "+221 77 123 45 67" in out and "1234567890123" in out


def test_open_hides_private_keys_by_default(ra_home, with_private, capsys):
    run("--ra-home", ra_home, "open", with_private)
    out = capsys.readouterr().out
    assert "--reveal pour tout voir" in out


def test_open_reveal_shows_the_full_keys(ra_home, reg, with_private, capsys):
    from sn import keystore
    expected = keystore.load(with_private).unlock(PW_R).sk_sd.hex()
    run("--ra-home", ra_home, "open", with_private, "--reveal")
    out = capsys.readouterr().out
    assert expected in out and "Efface ton terminal" in out


def test_open_refuses_a_wrong_password(ra_home, with_private, monkeypatch, capsys):
    monkeypatch.setenv("SN_PASSWORD", "pas-le-bon")
    assert run("--ra-home", ra_home, "open", with_private) == 2
    out = capsys.readouterr().out
    assert "mot de passe incorrect" in out
    assert "1234567890123" not in out          # rien n'a fuite
    assert "Amadou Ba" in out                  # le public reste visible


def test_open_public_only_asks_nothing(ra_home, with_private, monkeypatch, capsys):
    monkeypatch.delenv("SN_PASSWORD", raising=False)
    assert run("--ra-home", ra_home, "open", with_private, "--public") == 0
    out = capsys.readouterr().out
    assert "Amadou Ba" in out and "1234567890123" not in out


def test_open_an_exported_certificate_has_no_private_part(
    ra_home, reg, with_private, tmp_path, capsys
):
    public = tmp_path / "public.pem"
    run("--register", reg, "account", "export", "--cert", with_private, "-o", public)
    capsys.readouterr()
    assert run("--ra-home", ra_home, "open", public) == 0
    out = capsys.readouterr().out
    assert "aucune partie masquee" in out
    assert "Amadou Ba" in out and "1234567890123" not in out


def test_open_reports_a_faked_header(ra_home, with_private, tmp_path, capsys):
    faked = tmp_path / "faux.pem"
    faked.write_text(with_private.read_text().replace("Name: Amadou Ba", "Name: X"))
    assert run("--ra-home", ra_home, "open", faked, "--public") == 1
    assert "en-tetes lisibles falsifies" in capsys.readouterr().out


def test_open_rejects_garbage(ra_home, tmp_path, capsys):
    bad = tmp_path / "bad.pem"
    bad.write_text("ceci n'est pas un certificat")
    assert run("--ra-home", ra_home, "open", bad) == 2
    assert "illisible" in capsys.readouterr().out


def test_init_rejects_malformed_private_option(ra_home, reg, monkeypatch):
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    with pytest.raises(SystemExit):
        run("--ra-home", ra_home, "--register", reg, "init",
            "--name", "X", "--email", "x@y.sn", "--role", "R", "--org", "O",
            "--private", "pas-de-signe-egal")


def test_init_takes_the_fixed_private_options(ra_home, reg, monkeypatch, capsys):
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    assert run("--ra-home", ra_home, "--register", reg, "init",
               "--name", "Rosly", "--email", "r@ugb.sn",
               "--role", "Etudiant", "--org", "AIMS",
               "--telephone", "+221 77 123 45 67",
               "--adresse", "Saint-Louis",
               "--cni", "A1234567") == 0
    capsys.readouterr()
    from sn import keystore
    private = keystore.load(keystore.discover(reg)[0]).unlock(PW_R).private
    assert private == {
        "telephone": "+221 77 123 45 67",
        "adresse": "Saint-Louis",
        "cni_passeport": "A1234567",
    }


def test_private_fields_are_optional(ra_home, reg, monkeypatch, capsys):
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    run("--ra-home", ra_home, "--register", reg, "init",
        "--name", "Rosly", "--email", "r@ugb.sn",
        "--role", "Etudiant", "--org", "AIMS", "--telephone", "+221 77 000")
    capsys.readouterr()
    from sn import keystore
    assert keystore.load(keystore.discover(reg)[0]).unlock(PW_R).private == {
        "telephone": "+221 77 000"
    }


# --- titre et numero d'ordre ------------------------------------------------


def test_sign_records_title_and_order_number(reg, rosly, doc, tmp_path, capsys):
    png = tmp_path / "ev.png"
    assert run("--register", reg, "sign", doc, "--cert", rosly,
               "--title", "Contrat de prestation", "--ref", "2026-001",
               "-o", png) == 0
    out = capsys.readouterr().out
    assert "Contrat de prestation" in out and "2026-001" in out

    assert run("--register", reg, "verify", doc, "--qr", png) == 0
    out = capsys.readouterr().out
    assert "Contrat de prestation" in out and "2026-001" in out


def test_order_number_is_optional(reg, rosly, doc, tmp_path, capsys):
    png = tmp_path / "ev.png"
    assert run("--register", reg, "sign", doc, "--cert", rosly,
               "--title", "Note interne", "--ref", "", "-o", png) == 0
    capsys.readouterr()
    assert run("--register", reg, "verify", doc, "--qr", png) == 0
    out = capsys.readouterr().out
    assert "Note interne" in out and "numero" not in out


def test_sign_asks_for_title_interactively(reg, rosly, doc, tmp_path, capsys, monkeypatch):
    answers = iter(["Contrat signe", "2026-042"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    png = tmp_path / "ev.png"
    assert run("--register", reg, "sign", doc, "--cert", rosly, "-o", png) == 0
    capsys.readouterr()
    run("--register", reg, "verify", doc, "--qr", png)
    out = capsys.readouterr().out
    assert "Contrat signe" in out and "2026-042" in out


def test_inspect_shows_title_and_number(reg, rosly, doc, tmp_path, capsys):
    png = tmp_path / "ev.png"
    run("--register", reg, "sign", doc, "--cert", rosly,
        "--title", "Contrat", "--ref", "2026-007", "-o", png)
    capsys.readouterr()
    run("--register", reg, "inspect", "--qr", png)
    out = capsys.readouterr().out
    assert "titre" in out and "Contrat" in out and "2026-007" in out


def test_old_evidence_version_fails_cleanly(reg, rosly, doc, tmp_path, capsys):
    """Une preuve d'une version precedente doit donner un message, pas un crash."""
    from sn import qr
    png = tmp_path / "ev.png"
    run("--register", reg, "sign", doc, "--cert", rosly, "--title", "T", "--ref", "", "-o", png)
    capsys.readouterr()
    blob = bytearray(qr.read(png))
    blob[4] = 1  # le premier champ est l'octet de version
    old = tmp_path / "vieux.png"
    qr.write(bytes(blob), old)

    assert run("--register", reg, "inspect", "--qr", old) == 2
    assert "version 1" in capsys.readouterr().out
    assert run("--register", reg, "verify", doc, "--qr", old) == 2
    assert "version 1" in capsys.readouterr().out


# --- mode PDF ---------------------------------------------------------------


@pytest.fixture
def pdf(tmp_path):
    import shutil
    target = tmp_path / "attestation.pdf"
    shutil.copy(Path(__file__).parent / "sample.pdf", target)
    return target


def test_pdf_sign_then_verify(reg, rosly, pdf, capsys):
    assert run("--register", reg, "sign", pdf, "--pdf", "--cert", rosly,
               "--title", "Attestation", "--ref", "No 007/26") == 0
    out = capsys.readouterr().out
    signed = pdf.with_name("attestation-signe.pdf")
    assert signed.exists() and "bottom-right" in out

    assert run("--register", reg, "verify", signed, "--pdf") == 0
    out = capsys.readouterr().out
    assert "AUTHENTIQUE" in out and "Attestation" in out and "No 007/26" in out


def test_pdf_keeps_the_original_bytes(reg, rosly, pdf, capsys):
    original = pdf.read_bytes()
    run("--register", reg, "sign", pdf, "--pdf", "--cert", rosly,
        "--title", "T", "--ref", "")
    capsys.readouterr()
    signed = pdf.with_name("attestation-signe.pdf").read_bytes()
    assert signed[: len(original)] == original
    assert len(signed) > len(original)


def test_pdf_verify_writes_the_signed_prefix(reg, rosly, pdf, capsys):
    original = pdf.read_bytes()
    run("--register", reg, "sign", pdf, "--pdf", "--cert", rosly,
        "--title", "T", "--ref", "")
    capsys.readouterr()
    signed = pdf.with_name("attestation-signe.pdf")
    run("--register", reg, "verify", signed, "--pdf")
    extracted = signed.with_name("attestation-signe-verifie.pdf")
    assert extracted.exists()
    assert extracted.read_bytes() == original   # exactement ce qui fut signe


def test_pdf_detects_a_change_inside_the_signed_region(reg, rosly, pdf, capsys):
    run("--register", reg, "sign", pdf, "--pdf", "--cert", rosly,
        "--title", "T", "--ref", "")
    capsys.readouterr()
    signed = pdf.with_name("attestation-signe.pdf")
    data = bytearray(signed.read_bytes())
    data[len(pdf.read_bytes()) // 2] ^= 0x01
    signed.write_bytes(bytes(data))
    assert run("--register", reg, "verify", signed, "--pdf") == 1
    assert "NON AUTHENTIQUE" in capsys.readouterr().out


def test_pdf_verify_warns_about_the_unsigned_tail(reg, rosly, pdf, capsys):
    run("--register", reg, "sign", pdf, "--pdf", "--cert", rosly,
        "--title", "T", "--ref", "")
    capsys.readouterr()
    run("--register", reg, "verify", pdf.with_name("attestation-signe.pdf"), "--pdf")
    out = capsys.readouterr().out
    assert "rendu et objets conformes" in out


def test_pdf_position_and_page_options(reg, rosly, pdf, tmp_path, capsys):
    out_pdf = tmp_path / "coin.pdf"
    assert run("--register", reg, "sign", pdf, "--pdf", "--cert", rosly,
               "--title", "T", "--ref", "", "--position", "top-left",
               "--margin", "25", "--qr-size", "80", "-o", out_pdf) == 0
    assert "top-left" in capsys.readouterr().out
    assert run("--register", reg, "verify", out_pdf, "--pdf") == 0


def test_pdf_verify_on_a_plain_pdf_fails_cleanly(reg, rosly, pdf, capsys):
    assert run("--register", reg, "verify", pdf, "--pdf") == 2
    assert "aucune preuve" in capsys.readouterr().out


def test_pdf_with_certificate_binds_the_identity(
    ra_home, reg, rosly, pdf, tmp_path, capsys
):
    cert = tmp_path / "public.pem"
    run("--register", reg, "account", "export", "-o", cert)
    run("--register", reg, "sign", pdf, "--pdf", "--cert", rosly,
        "--title", "T", "--ref", "")
    capsys.readouterr()
    signed = pdf.with_name("attestation-signe.pdf")
    assert run("--ra-home", ra_home, "--register", reg, "verify",
               signed, "--pdf", "--cert", cert) == 0
    out = capsys.readouterr().out
    assert "cle liee ✓" in out and "certificat ✓" in out


def test_pdf_rejects_content_appended_after_signing(reg, rosly, pdf, capsys):
    """PDF shadow attack : octets signes intacts, mais contenu ajoute."""
    from tests.test_pdfsign import _append_revision
    run("--register", reg, "sign", pdf, "--pdf", "--cert", rosly,
        "--title", "T", "--ref", "")
    capsys.readouterr()
    signed = pdf.with_name("attestation-signe.pdf")

    assert run("--register", reg, "verify", signed, "--pdf") == 0
    assert "revisions ✓" in capsys.readouterr().out

    _append_revision(signed, "PIRATE")
    assert run("--register", reg, "verify", signed, "--pdf") == 1
    out = capsys.readouterr().out
    assert "NON AUTHENTIQUE" in out and "revisions ✗" in out
    assert "ajout" in out
    # la signature elle-meme reste valide : c'est bien le compte qui sauve
    assert "signature ✓" in out


def test_pdf_rejects_evidence_meant_for_a_non_pdf(reg, rosly, pdf, tmp_path, capsys):
    """Le QR d'un fichier ordinaire recolle sur un PDF."""
    from sn import pdfsign, qr
    txt = tmp_path / "note.txt"; txt.write_text("un simple texte")
    png = tmp_path / "note.png"
    run("--register", reg, "sign", txt, "--cert", rosly,
        "--title", "T", "--ref", "", "-o", png)
    capsys.readouterr()
    greffe = tmp_path / "greffe.pdf"
    pdfsign.embed_qr(pdf, qr.encode_payload(qr.read(png)), greffe)

    assert run("--register", reg, "verify", greffe, "--pdf") == 2
    assert "hors PDF" in capsys.readouterr().out


def test_pdf_rejects_the_qr_of_another_pdf_of_the_same_size(
    reg, rosly, pdf, tmp_path, capsys
):
    """Meme longueur de prefixe, contenu different : la signature tombe."""
    from sn import pdfsign, qr
    other = tmp_path / "autre.pdf"
    data = bytearray(pdf.read_bytes())
    data[len(data) // 2 : len(data) // 2 + 6] = b"ZZZZZZ"
    other.write_bytes(bytes(data))
    assert len(other.read_bytes()) == len(pdf.read_bytes())

    run("--register", reg, "sign", other, "--pdf", "--cert", rosly,
        "--title", "Autre", "--ref", "")
    capsys.readouterr()
    signed_other = other.with_name("autre-signe.pdf")

    greffe = tmp_path / "greffe.pdf"
    pdfsign.embed_qr(
        pdf, qr.encode_payload(pdfsign.extract_payload(signed_other)), greffe
    )
    assert run("--register", reg, "verify", greffe, "--pdf") == 1
    out = capsys.readouterr().out
    assert "signature ✗" in out and "revisions ✓" in out


# --- zone non signee : rendu et objets actifs -------------------------------


def test_pdf_verify_reports_the_three_tail_checks(reg, rosly, pdf, capsys):
    run("--register", reg, "sign", pdf, "--pdf", "--cert", rosly,
        "--title", "T", "--ref", "")
    capsys.readouterr()
    signed = pdf.with_name("attestation-signe.pdf")
    assert run("--register", reg, "verify", signed, "--pdf") == 0
    out = capsys.readouterr().out
    assert "revisions ✓" in out and "visuel ✓" in out and "objets ✓" in out


def test_pdf_rejects_a_banner_merged_into_the_qr_revision(reg, rosly, pdf, capsys):
    """L'attaque qui passait le compte de revisions."""
    from tests.test_pdfcheck import _overlay_page
    import io, segno
    from PIL import Image
    from pypdf import PdfReader, PdfWriter, Transformation
    from sn import pdfsign, qr

    run("--register", reg, "sign", pdf, "--pdf", "--cert", rosly,
        "--title", "T", "--ref", "")
    capsys.readouterr()
    signed = pdf.with_name("attestation-signe.pdf")
    payload = qr.encode_payload(pdfsign.extract_payload(signed))

    png = io.BytesIO()
    segno.make(payload, error="m").save(png, kind="png", scale=6, border=2)
    png.seek(0)
    b = io.BytesIO(); Image.open(png).convert("1").save(b, format="PDF"); b.seek(0)
    qr_page = PdfReader(b).pages[0]

    fusion = pdf.with_name("fusion.pdf")
    w = PdfWriter(str(pdf), incremental=True)
    page = w.pages[0]
    pw = float(page.mediabox.width)
    page.merge_transformed_page(
        qr_page,
        Transformation().scale(100.0 / float(qr_page.mediabox.width)).translate(pw - 110, 10))
    ov = _overlay_page("PIRATE INCONNU")
    page.merge_transformed_page(
        ov, Transformation().scale(300.0 / float(ov.mediabox.width)).translate(80, 700))
    w.write(str(fusion))

    assert run("--register", reg, "verify", fusion, "--pdf") == 1
    out = capsys.readouterr().out
    assert "revisions ✓" in out and "visuel ✗" in out


def test_pdf_rejects_javascript_merged_into_the_qr_revision(reg, rosly, pdf, capsys):
    """Invisible et compte de revisions conforme : seuls les objets la voient."""
    import io, segno
    from PIL import Image
    from pypdf import PdfReader, PdfWriter, Transformation
    from pypdf.actions import JavaScript
    from sn import pdfsign, qr

    run("--register", reg, "sign", pdf, "--pdf", "--cert", rosly,
        "--title", "T", "--ref", "")
    capsys.readouterr()
    signed = pdf.with_name("attestation-signe.pdf")
    payload = qr.encode_payload(pdfsign.extract_payload(signed))

    png = io.BytesIO()
    segno.make(payload, error="m").save(png, kind="png", scale=6, border=2)
    png.seek(0)
    b = io.BytesIO(); Image.open(png).convert("1").save(b, format="PDF"); b.seek(0)
    qr_page = PdfReader(b).pages[0]

    piege = pdf.with_name("piege.pdf")
    w = PdfWriter(str(pdf), incremental=True)
    page = w.pages[0]
    pw = float(page.mediabox.width)
    page.merge_transformed_page(
        qr_page,
        Transformation().scale(100.0 / float(qr_page.mediabox.width)).translate(pw - 110, 10))
    w.add_open_action(JavaScript("app.launchURL('https://phishing.example');"))
    w.write(str(piege))

    assert run("--register", reg, "verify", piege, "--pdf") == 1
    out = capsys.readouterr().out
    assert "revisions ✓" in out and "visuel ✓" in out and "objets ✗" in out
    assert "JavaScript" in out


# --- mode chiffre -----------------------------------------------------------


@pytest.fixture
def deux_comptes(ra_home, reg, monkeypatch, capsys, tmp_path):
    """Un expediteur et un destinataire, avec leurs certificats publics."""
    from sn import keystore
    for name, email, pw in [("Rosly", "rosly@ugb.sn", PW_R),
                            ("Fatou", "fatou@ugb.sn", PW_F)]:
        monkeypatch.setenv("SN_PASSWORD", pw)
        run("--ra-home", ra_home, "--register", reg, "init",
            "--name", name, "--email", email, "--role", "R", "--org", "UGB")
    capsys.readouterr()
    certs = {}
    for email in ("rosly@ugb.sn", "fatou@ugb.sn"):
        who = email.split("@")[0]
        compte = next(p for p in keystore.discover(reg) if who in p.name)
        out = tmp_path / f"{who}.pem"
        run("--register", reg, "account", "export", "--cert", compte, "-o", out)
        certs[email] = out
        certs[who] = compte          # le compte, avec sa cle privee
    capsys.readouterr()
    assert len(keystore.discover(reg)) == 2
    return certs


@pytest.fixture
def secret(tmp_path):
    p = tmp_path / "rapport.txt"
    p.write_text("RAPPORT CONFIDENTIEL\nBudget : 12500 EUR\n")
    return p


def test_encrypt_then_decrypt(ra_home, reg, deux_comptes, secret, tmp_path,
                              monkeypatch, capsys):
    snc = tmp_path / "rapport.snc"
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    assert run("--ra-home", ra_home, "--register", reg, "encrypt", secret,
               "--to", deux_comptes["fatou@ugb.sn"], "--cert", deux_comptes["rosly"],
               "--title", "Rapport", "--ref", "No 1", "-o", snc) == 0
    capsys.readouterr()

    # le document n'est nulle part en clair
    blob = snc.read_bytes()
    assert b"12500" not in blob and b"CONFIDENTIEL" not in blob

    recu = tmp_path / "recu.txt"
    monkeypatch.setenv("SN_PASSWORD", PW_F)
    assert run("--register", reg, "decrypt", snc, "--cert", deux_comptes["fatou"],
               "-o", recu) == 0
    out = capsys.readouterr().out
    assert "OUVERT ET AUTHENTIFIE" in out and "Rosly" in out
    assert recu.read_bytes() == secret.read_bytes()


def test_a_third_party_cannot_decrypt(ra_home, reg, deux_comptes, secret,
                                      tmp_path, monkeypatch, capsys):
    snc = tmp_path / "rapport.snc"
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    run("--ra-home", ra_home, "--register", reg, "encrypt", secret,
        "--to", deux_comptes["fatou@ugb.sn"], "--cert", deux_comptes["rosly"],
        "--title", "T", "--ref", "", "-o", snc)
    capsys.readouterr()
    # Rosly lui-meme ne peut pas relire ce qu'il a envoye
    assert run("--register", reg, "decrypt", snc, "--cert", deux_comptes["rosly"]) == 1
    assert "pas ete chiffre pour ce compte" in capsys.readouterr().out


def test_tampered_snc_is_refused(ra_home, reg, deux_comptes, secret,
                                 tmp_path, monkeypatch, capsys):
    snc = tmp_path / "rapport.snc"
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    run("--ra-home", ra_home, "--register", reg, "encrypt", secret,
        "--to", deux_comptes["fatou@ugb.sn"], "--cert", deux_comptes["rosly"],
        "--title", "T", "--ref", "", "-o", snc)
    capsys.readouterr()
    data = bytearray(snc.read_bytes()); data[len(data) // 2] ^= 0x01
    snc.write_bytes(bytes(data))

    monkeypatch.setenv("SN_PASSWORD", PW_F)
    assert run("--register", reg, "decrypt", snc, "--cert", deux_comptes["fatou"]) == 1
    assert "CONTENU REFUSE" in capsys.readouterr().out


def test_arbitration_establishes_the_origin(ra_home, reg, deux_comptes, secret,
                                            tmp_path, monkeypatch, capsys):
    """Le scenario du papier : le destinataire prouve l'origine a un tiers."""
    snc, recu, preuve = (tmp_path / "r.snc", tmp_path / "recu.txt",
                         tmp_path / "preuve.nr")
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    run("--ra-home", ra_home, "--register", reg, "encrypt", secret,
        "--to", deux_comptes["fatou@ugb.sn"], "--cert", deux_comptes["rosly"],
        "--title", "Rapport", "--ref", "", "-o", snc)
    monkeypatch.setenv("SN_PASSWORD", PW_F)
    run("--register", reg, "decrypt", snc, "--cert", deux_comptes["fatou"],
        "-o", recu, "--proof", preuve)
    capsys.readouterr()

    # l'arbitre n'a aucun mot de passe
    monkeypatch.delenv("SN_PASSWORD", raising=False)
    assert run("--ra-home", ra_home, "arbitrate", snc, "--document", recu,
               "--proof", preuve, "--cert", deux_comptes["rosly@ugb.sn"]) == 0
    out = capsys.readouterr().out
    assert "ORIGINE ETABLIE" in out and "cle liee ✓" in out


def test_arbitration_refuses_a_different_document(ra_home, reg, deux_comptes,
                                                  secret, tmp_path, monkeypatch,
                                                  capsys):
    snc, recu, preuve = (tmp_path / "r.snc", tmp_path / "recu.txt",
                         tmp_path / "preuve.nr")
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    run("--ra-home", ra_home, "--register", reg, "encrypt", secret,
        "--to", deux_comptes["fatou@ugb.sn"], "--cert", deux_comptes["rosly"],
        "--title", "T", "--ref", "", "-o", snc)
    monkeypatch.setenv("SN_PASSWORD", PW_F)
    run("--register", reg, "decrypt", snc, "--cert", deux_comptes["fatou"],
        "-o", recu, "--proof", preuve)
    capsys.readouterr()

    faux = tmp_path / "faux.txt"
    faux.write_text("RAPPORT CONFIDENTIEL\nBudget : 99000 EUR\n")
    assert run("--ra-home", ra_home, "arbitrate", snc, "--document", faux,
               "--proof", preuve, "--cert", deux_comptes["rosly@ugb.sn"]) == 1
    assert "ORIGINE NON ETABLIE" in capsys.readouterr().out


def test_encrypt_refuses_an_invalid_recipient_certificate(
    ra_home, reg, deux_comptes, secret, tmp_path, monkeypatch, capsys
):
    faux = tmp_path / "faux.pem"
    faux.write_text(
        deux_comptes["fatou@ugb.sn"].read_text().replace("Name: Fatou", "Name: X"))
    monkeypatch.setenv("SN_PASSWORD", PW_R)
    with pytest.raises(SystemExit):
        run("--ra-home", ra_home, "--register", reg, "encrypt", secret,
            "--to", faux, "--cert", deux_comptes["rosly"], "--title", "T", "--ref", "")
