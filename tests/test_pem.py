"""Format PEM avec en-tetes lisibles."""

import os

import pytest

from sn import pem


def test_roundtrip():
    body = os.urandom(300)
    text = pem.encode("SN CERTIFICATE", {"Name": "Rosly"}, body)
    headers, back = pem.decode_one(text, "SN CERTIFICATE")
    assert back == body and headers == {"Name": "Rosly"}


def test_headers_are_human_readable():
    text = pem.encode("SN CERTIFICATE", {"Name": "Rosly", "Email": "r@ugb.sn"}, b"x")
    assert "Name: Rosly" in text and "Email: r@ugb.sn" in text


def test_several_blocks_in_one_file():
    text = pem.encode("SN CERTIFICATE", {}, b"cert") + pem.encode(
        "SN ENCRYPTED PRIVATE KEY", {}, b"key"
    )
    tags = [b[0] for b in pem.decode_all(text)]
    assert tags == ["SN CERTIFICATE", "SN ENCRYPTED PRIVATE KEY"]
    assert pem.decode_one(text, "SN ENCRYPTED PRIVATE KEY")[1] == b"key"


def test_header_injection_is_blocked():
    """Une valeur multi-ligne pourrait forger de faux en-tetes."""
    with pytest.raises(pem.PemError):
        pem.encode("X", {"Name": "Rosly\nRole: Directeur"}, b"")
    with pytest.raises(pem.PemError):
        pem.encode("X", {"Na:me": "x"}, b"")


def test_missing_block_is_an_error():
    text = pem.encode("SN CERTIFICATE", {}, b"x")
    with pytest.raises(pem.PemError):
        pem.decode_one(text, "SN ENCRYPTED PRIVATE KEY")
    assert pem.has_block(text, "SN CERTIFICATE")
    assert not pem.has_block(text, "SN ENCRYPTED PRIVATE KEY")


def test_duplicate_blocks_are_an_error():
    text = pem.encode("SN CERTIFICATE", {}, b"a") * 2
    with pytest.raises(pem.PemError):
        pem.decode_one(text, "SN CERTIFICATE")


def test_corrupt_base64_is_an_error():
    text = pem.encode("SN CERTIFICATE", {}, b"hello").replace("aGVsbG8=", "!!!!")
    with pytest.raises(pem.PemError):
        pem.decode_all(text)
