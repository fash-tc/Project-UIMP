import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from secretbox import SecretBox, derive_fernet_key


def test_derive_fernet_key_is_deterministic():
    k1 = derive_fernet_key("master-secret-abc")
    k2 = derive_fernet_key("master-secret-abc")
    assert k1 == k2
    assert len(k1) == 44  # base64url-encoded 32 bytes


def test_derive_fernet_key_different_inputs_different_keys():
    assert derive_fernet_key("a") != derive_fernet_key("b")


def test_secretbox_roundtrip():
    box = SecretBox("master-secret-abc")
    cipher = box.encrypt(b"hello world")
    assert cipher != b"hello world"
    assert box.decrypt(cipher) == b"hello world"


def test_secretbox_rejects_tampered_ciphertext():
    box = SecretBox("master-secret-abc")
    cipher = bytearray(box.encrypt(b"hello"))
    cipher[-1] ^= 0x01  # flip a bit
    with pytest.raises(Exception):  # cryptography raises InvalidToken
        box.decrypt(bytes(cipher))


def test_secretbox_rejects_wrong_key():
    a = SecretBox("master-a").encrypt(b"hello")
    with pytest.raises(Exception):
        SecretBox("master-b").decrypt(a)
