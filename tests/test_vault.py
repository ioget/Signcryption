"""Chiffrement des cles privees par mot de passe."""

import pytest

from sn import vault


def test_roundtrip():
    blob = vault.seal("un bon mot de passe", b"materiel de cle")
    assert vault.unseal("un bon mot de passe", blob) == b"materiel de cle"


def test_wrong_password_is_rejected():
    blob = vault.seal("le bon", b"secret")
    with pytest.raises(vault.BadPassword):
        vault.unseal("le mauvais", blob)


def test_plaintext_never_appears_in_the_blob():
    blob = vault.seal("mot de passe", b"CLE-TRES-SECRETE")
    assert b"CLE-TRES-SECRETE".hex() not in blob["ciphertext"]
    assert "CLE-TRES-SECRETE" not in str(blob)


def test_aad_is_authenticated():
    """Le coffre est lie a son certificat ; on ne peut pas le recoller."""
    blob = vault.seal("mdp", b"secret", aad=b"serial-A")
    assert vault.unseal("mdp", blob, aad=b"serial-A") == b"secret"
    with pytest.raises(vault.BadPassword):
        vault.unseal("mdp", blob, aad=b"serial-B")


def test_tampering_with_the_ciphertext_is_detected():
    blob = vault.seal("mdp", b"secret")
    ct = bytearray(bytes.fromhex(blob["ciphertext"]))
    ct[0] ^= 0x01
    blob["ciphertext"] = bytes(ct).hex()
    with pytest.raises(vault.BadPassword):
        vault.unseal("mdp", blob)


def test_same_password_gives_different_ciphertexts():
    """Sel et nonce aleatoires a chaque fois."""
    a = vault.seal("mdp", b"secret")
    b = vault.seal("mdp", b"secret")
    assert a["ciphertext"] != b["ciphertext"]
    assert a["kdf"]["salt"] != b["kdf"]["salt"]


@pytest.mark.parametrize(
    "password,expected_warning",
    [("court", True), ("12345678901", True), ("abcdefghijk", True),
     ("Mot2Passe!ok", False)],
)
def test_strength_check(password, expected_warning):
    assert (vault.check_strength(password) is not None) == expected_warning
