"""Encoding must be unambiguous -- the hash's collision resistance leans on it."""

import os

import pytest

from sn.codec import b45decode, b45encode, pack, unpack


def test_roundtrip():
    items = [b"", b"a", os.urandom(1000)]
    assert unpack(pack(*items), count=3) == items


def test_pack_is_unambiguous():
    # This is the whole point: concatenation alone would make these equal,
    # which would hand an attacker a free hash collision between two
    # different (c1, c2) splits.
    assert pack(b"ab", b"c") != pack(b"a", b"bc")
    assert b"ab" + b"c" == b"a" + b"bc"


def test_unpack_rejects_malformed():
    with pytest.raises(ValueError):
        unpack(b"\x00\x00\x00")  # truncated length prefix
    with pytest.raises(ValueError):
        unpack(b"\x00\x00\x00\x05ab")  # truncated field
    with pytest.raises(ValueError):
        unpack(pack(b"a"), count=2)  # wrong field count


@pytest.mark.parametrize("n", [0, 1, 2, 3, 17, 354, 1000, 7727])
def test_base45_roundtrip(n):
    data = os.urandom(n)
    assert b45decode(b45encode(data)) == data


def test_base45_uses_qr_alphanumeric_charset():
    qr_alnum = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:")
    assert set(b45encode(os.urandom(500))) <= qr_alnum


def test_base45_rejects_garbage():
    with pytest.raises(ValueError):
        b45decode("abc")  # lowercase is outside the alphabet
    with pytest.raises(ValueError):
        b45decode("0000")  # length % 3 == 1 is impossible
