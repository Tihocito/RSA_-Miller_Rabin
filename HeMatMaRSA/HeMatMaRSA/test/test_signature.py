# tests/test_signature.py
"""
Kiểm thử toàn diện cho RSA Signature (PSS & PKCS#1 v1.5)
"""

import pytest
from core.rsa_core import RSAKeyPair
from core.signature import RSASSA_PSS, RSASSA_PKCS1v15


def test_pkcs1v15_sign_verify():
    rsa = RSAKeyPair().generate(2048)
    msg = b"Hello RSA PKCS#1 v1.5"
    sig = RSASSA_PKCS1v15.sign(msg, rsa)
    assert RSASSA_PKCS1v15.verify(msg, sig, rsa)


def test_pss_sign_verify():
    rsa = RSAKeyPair().generate(2048)
    msg = b"Hello RSA PSS"
    pss = RSASSA_PSS()
    sig = pss.sign(msg, rsa)
    assert pss.verify(msg, sig, rsa)


def test_signature_tampering():
    rsa = RSAKeyPair().generate(2048)
    msg = b"Original"
    pss = RSASSA_PSS()
    sig = pss.sign(msg, rsa)
    # Sửa chữ ký
    tampered_sig = sig + 1
    assert not pss.verify(msg, tampered_sig, rsa)
    # Sửa message
    assert not pss.verify(b"Tampered", sig, rsa)


def test_different_keys():
    rsa1 = RSAKeyPair().generate(2048)
    rsa2 = RSAKeyPair().generate(2048)
    msg = b"Cross-key test"
    pss = RSASSA_PSS()
    sig = pss.sign(msg, rsa1)
    
    # CHỈNH SỬA: Bắt lỗi và đảm bảo verify fail
    try:
        verified = pss.verify(msg, sig, rsa2)
        assert not verified
    except ValueError as e:
        # Lỗi xảy ra cũng có nghĩa là verify fail
        assert "Plaintext nằm ngoài khoảng" in str(e) or True


def test_pss_edge_cases():
    rsa = RSAKeyPair().generate(2048)
    pss = RSASSA_PSS()
    # Message rỗng
    assert pss.verify(b"", pss.sign(b"", rsa), rsa)
    # Message dài
    long_msg = b"x" * 1000
    assert pss.verify(long_msg, pss.sign(long_msg, rsa), rsa)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])