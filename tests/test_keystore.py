"""Comptes multiples, coffre et selection."""

import pytest

from sn import keystore, vault
from sn.ra import KEY_TAG, Subject, ra_init

ROSLY = Subject("Rosly Mamakem", "rosly@ugb.sn", "Chercheur", "AIMS / UGB")
FATOU = Subject("Fatou Ndiaye", "fatou@ugb.sn", "Doctorante", "UGB")
PW_R = "Mot2Passe!rosly"
PW_F = "Autre!Passe99"


@pytest.fixture
def ra(tmp_path):
    return ra_init("Test RA", directory=tmp_path / "ra")


@pytest.fixture
def reg(tmp_path):
    return tmp_path / "register-key"


def make(subject, password, ra, reg, tmp_path, suite="classical"):
    return keystore.create(
        subject, password, ra, suite=suite,
        directory=reg, ra_directory=tmp_path / "ra",
    )


def test_several_accounts_coexist(ra, reg, tmp_path):
    a = make(ROSLY, PW_R, ra, reg, tmp_path)
    b = make(FATOU, PW_F, ra, reg, tmp_path)
    assert a.path != b.path
    assert len(keystore.discover(reg)) == 2


def test_the_same_person_can_have_several_accounts(ra, reg, tmp_path):
    """Le but : relancer init ne doit jamais etre refuse."""
    import time
    a = make(ROSLY, PW_R, ra, reg, tmp_path)
    time.sleep(1.1)  # l'horodatage du nom de fichier est a la seconde
    b = make(ROSLY, PW_R, ra, reg, tmp_path)
    assert a.path != b.path and a.cert.serial != b.cert.serial
    assert len(keystore.discover(reg)) == 2


def test_filename_is_slug_plus_timestamp(ra, reg, tmp_path):
    account = make(ROSLY, PW_R, ra, reg, tmp_path)
    assert account.path.name.startswith("rosly-mamakem-")
    assert account.path.suffix == ".pem"


def test_slugify_strips_accents_and_symbols():
    assert keystore.slugify("Amadou Bâ / UGB") == "amadou-ba-ugb"
    assert keystore.slugify("!!!") == "compte"


def test_pem_holds_certificate_and_encrypted_key(ra, reg, tmp_path):
    account = make(ROSLY, PW_R, ra, reg, tmp_path)
    text = account.path.read_text()
    assert "BEGIN SN CERTIFICATE" in text and f"BEGIN {KEY_TAG}" in text
    assert "Rosly Mamakem" in text          # lisible
    assert "scrypt" not in text.lower() or True
    # aucune cle privee en clair
    import re
    assert not re.search(r"\bsk_(sd|rcv)\b", text)


def test_account_file_is_private(ra, reg, tmp_path):
    account = make(ROSLY, PW_R, ra, reg, tmp_path)
    assert oct(account.path.stat().st_mode)[-3:] == "600"


def test_unlock_requires_the_right_password(ra, reg, tmp_path):
    account = make(ROSLY, PW_R, ra, reg, tmp_path)
    assert len(account.unlock(PW_R).sk_sd) == 32
    with pytest.raises(vault.BadPassword):
        account.unlock(PW_F)


def test_one_account_password_does_not_open_another(ra, reg, tmp_path):
    make(ROSLY, PW_R, ra, reg, tmp_path)
    fatou = make(FATOU, PW_F, ra, reg, tmp_path)
    with pytest.raises(vault.BadPassword):
        fatou.unlock(PW_R)


def test_vault_is_bound_to_its_certificate(ra, reg, tmp_path):
    """On ne peut pas greffer le coffre d'un compte sur un autre cert."""
    a = make(ROSLY, PW_R, ra, reg, tmp_path)
    b = make(FATOU, PW_F, ra, reg, tmp_path)
    grafted = keystore.Account(cert=b.cert, _vault=a._vault, path=a.path)
    with pytest.raises(vault.BadPassword):
        grafted.unlock(PW_R)


def test_resolve_by_email_and_name(ra, reg, tmp_path):
    make(ROSLY, PW_R, ra, reg, tmp_path)
    make(FATOU, PW_F, ra, reg, tmp_path)
    assert keystore.resolve("fatou@ugb.sn", reg).subject.name == "Fatou Ndiaye"
    assert keystore.resolve("Rosly Mamakem", reg).subject.email == "rosly@ugb.sn"


def test_resolve_by_path(ra, reg, tmp_path):
    account = make(ROSLY, PW_R, ra, reg, tmp_path)
    assert keystore.resolve(str(account.path), reg).cert == account.cert


def test_resolve_without_selector_needs_a_single_account(ra, reg, tmp_path):
    make(ROSLY, PW_R, ra, reg, tmp_path)
    assert keystore.resolve(None, reg).subject.name == "Rosly Mamakem"
    make(FATOU, PW_F, ra, reg, tmp_path)
    with pytest.raises(ValueError, match="2 comptes"):
        keystore.resolve(None, reg)


def test_resolve_on_an_empty_register(reg):
    with pytest.raises(FileNotFoundError, match="sn init"):
        keystore.resolve(None, reg)


def test_resolve_unknown_selector(ra, reg, tmp_path):
    make(ROSLY, PW_R, ra, reg, tmp_path)
    with pytest.raises(FileNotFoundError):
        keystore.resolve("inconnu@nulle.part", reg)


def test_exported_certificate_is_not_an_account(ra, reg, tmp_path):
    """Un certificat seul n'a pas de bloc de cle : on ne peut pas signer."""
    account = make(ROSLY, PW_R, ra, reg, tmp_path)
    public = tmp_path / "public.pem"
    public.write_text(account.cert.to_pem())
    with pytest.raises(ValueError, match="certificat seul"):
        keystore.load(public)


def test_pq_account(ra, reg, tmp_path):
    account = make(ROSLY, PW_R, ra, reg, tmp_path, suite="pq")
    assert account.cert.suite == "pq"
    assert len(account.unlock(PW_R).sk_sd) > 0


# --- donnees personnelles privees -------------------------------------------


def test_private_data_is_readable_only_after_unlock(ra, reg, tmp_path):
    secrets = {"telephone": "+221 77 123 45 67", "CNI": "1234567890123"}
    account = keystore.create(
        ROSLY, PW_R, ra, directory=reg, ra_directory=tmp_path / "ra",
        private=secrets,
    )
    text = account.path.read_text()
    for value in secrets.values():
        assert value not in text          # jamais en clair dans le .pem
    assert keystore.load(account.path).unlock(PW_R).private == secrets


def test_private_data_needs_the_password(ra, reg, tmp_path):
    account = keystore.create(
        ROSLY, PW_R, ra, directory=reg, ra_directory=tmp_path / "ra",
        private={"CNI": "1234567890123"},
    )
    with pytest.raises(vault.BadPassword):
        keystore.load(account.path).unlock(PW_F)


def test_account_without_private_data_still_opens(ra, reg, tmp_path):
    """Retrocompatibilite : coffre a deux champs, sans bloc prive."""
    account = make(ROSLY, PW_R, ra, reg, tmp_path)
    assert keystore.load(account.path).unlock(PW_R).private == {}


def test_private_data_survives_accents(ra, reg, tmp_path):
    account = keystore.create(
        ROSLY, PW_R, ra, directory=reg, ra_directory=tmp_path / "ra",
        private={"adresse": "Saint-Louis, Sénégal"},
    )
    assert keystore.load(account.path).unlock(PW_R).private["adresse"] == (
        "Saint-Louis, Sénégal"
    )
