"""Autorite d'enregistrement : RA-sign et RA-verify."""

import pytest

from sn.pem import PemError
from sn.ra import (
    RA_DIR,
    REGISTER_DIR,
    Certificate,
    Subject,
    ra_init,
    ra_load,
    ra_sign,
    ra_verify,
    ra_verify_file,
)
from sn.primitives import get_suite

SUBJECT = Subject("Rosly Mamakem", "rosly@ugb.sn", "Chercheur", "AIMS / UGB")


@pytest.fixture
def ra(tmp_path):
    return ra_init("Test RA", directory=tmp_path)


@pytest.fixture
def keys():
    s = get_suite("classical")
    _, pk_sd = s.sig.generate()
    _, pk_rcv = s.kem.generate()
    return pk_sd, pk_rcv


@pytest.fixture
def cert(tmp_path, ra, keys):
    return ra_sign(ra, SUBJECT, "classical", *keys, directory=tmp_path)


# --- le RA lui-meme ---------------------------------------------------------


def test_ra_is_persisted(tmp_path, ra):
    back = ra_load(tmp_path)
    assert (back.pk, back.sk, back.tau0) == (ra.pk, ra.sk, ra.tau0)


def test_ra_init_refuses_to_overwrite(tmp_path, ra):
    with pytest.raises(FileExistsError):
        ra_init("Autre", directory=tmp_path)


def test_ra_key_file_is_private(tmp_path, ra):
    from sn.ra import ra_path
    assert oct(ra_path(tmp_path).stat().st_mode)[-3:] == "600"


def test_default_directories_are_as_specified():
    assert RA_DIR.name == ".ra"
    assert REGISTER_DIR.name == "register-key"


# --- RA-sign ----------------------------------------------------------------


def test_ra_sign_produces_a_valid_certificate(ra, cert):
    result = ra_verify(cert, ra)
    assert result.valid and result.signature_ok and result.issuer_matches


def test_certificate_carries_the_ra_domain_parameter(ra, cert):
    assert cert.tau0 == ra.tau0


def test_ra_sign_logs_every_certificate(tmp_path, ra, keys):
    a = ra_sign(ra, SUBJECT, "classical", *keys, directory=tmp_path)
    b = ra_sign(ra, SUBJECT, "classical", *keys, directory=tmp_path)
    assert a.serial != b.serial
    logged = {p.stem for p in (tmp_path / "issued").glob("*.pem")}
    assert {a.serial, b.serial} <= logged


# --- format PEM -------------------------------------------------------------


def test_certificate_pem_roundtrip(cert):
    back, mismatched = Certificate.from_pem(cert.to_pem())
    assert back == cert and mismatched == []


def test_personal_data_is_readable_in_the_pem(cert):
    text = cert.to_pem()
    for value in ("Rosly Mamakem", "rosly@ugb.sn", "Chercheur", "AIMS / UGB"):
        assert value in text


def test_pem_carries_no_private_key(cert):
    assert "PRIVATE" not in cert.to_pem()


def test_tampered_header_is_detected(ra, cert):
    """Les en-tetes ne sont pas signes, donc on verifie qu'ils collent."""
    faked = cert.to_pem().replace("Name: Rosly Mamakem", "Name: Pirate")
    back, mismatched = Certificate.from_pem(faked)
    assert mismatched == ["Name"]
    assert back.subject.name == "Rosly Mamakem"  # le corps dit la verite
    assert ra_verify(back, ra, mismatched).valid is False


# --- RA-verify --------------------------------------------------------------


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject", Subject("Pirate", "p@x.sn", "Directeur", "X")),
        ("not_after", "2099-01-01T00:00:00+00:00"),
        ("serial", "0" * 16),
    ],
)
def test_ra_verify_rejects_a_tampered_body(ra, cert, field, value):
    forged = Certificate(**{**cert.__dict__, field: value})
    assert ra_verify(forged, ra).valid is False


def test_ra_verify_rejects_a_swapped_public_key(ra, cert):
    """Le coeur du RA : on ne met pas sa cle dans le certificat d'un autre."""
    attacker_pk, _ = get_suite("classical").sig.generate()
    forged = Certificate(**{**cert.__dict__, "pk_sd": attacker_pk})
    assert ra_verify(forged, ra).valid is False


def test_ra_verify_rejects_another_ras_certificate(tmp_path, ra, keys):
    other = ra_init("Autre RA", directory=tmp_path / "other")
    foreign = ra_sign(other, SUBJECT, "classical", *keys, directory=tmp_path / "other")
    assert ra_verify(foreign).valid is True          # valide en soi
    assert ra_verify(foreign, ra).valid is False     # mais pas notre RA
    assert "autre RA" in " ".join(ra_verify(foreign, ra).problems)


def test_ra_verify_rejects_an_expired_certificate(tmp_path, ra, keys):
    old = ra_sign(ra, SUBJECT, "classical", *keys, days=-1, directory=tmp_path)
    result = ra_verify(old, ra)
    assert result.signature_ok is True and result.period_ok is False
    assert result.valid is False


def test_ra_verify_needs_no_secret(ra, cert):
    """RA-verify n'utilise que la cle publique du RA."""
    public_only = type(ra)(
        name=ra.name, suite=ra.suite, sk=b"", pk=ra.pk,
        tau0=ra.tau0, created=ra.created,
    )
    assert ra_verify(cert, public_only).valid is True


def test_ra_verify_file(tmp_path, ra, cert):
    path = tmp_path / "cert.pem"
    path.write_text(cert.to_pem())
    back, result = ra_verify_file(path, ra)
    assert back == cert and result.valid is True


def test_ra_verify_file_rejects_garbage(tmp_path, ra):
    path = tmp_path / "bad.pem"
    path.write_text("ceci n'est pas un certificat")
    with pytest.raises(PemError):
        ra_verify_file(path, ra)


def test_pq_ra_can_certify_a_classical_account(tmp_path, keys):
    pq_ra = ra_init("PQ RA", suite="pq", directory=tmp_path / "pq")
    cert = ra_sign(pq_ra, SUBJECT, "classical", *keys, directory=tmp_path / "pq")
    assert cert.issuer_suite == "pq"
    assert ra_verify(cert, pq_ra).valid is True
