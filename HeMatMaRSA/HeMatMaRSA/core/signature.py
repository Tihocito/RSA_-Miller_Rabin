# core/signature.py
"""
RSA Signature – PKCS#1 v2.2 (PSS & PKCS#1 v1.5)
"""

import hashlib
import os
from .oaep import mgf1

class RSASSA_PSS:
    """RSASSA-PSS với SHA-256 và salt tự động"""
    def __init__(self, hash_func=hashlib.sha256, mgf=mgf1, salt_len=None):
        self.hash_func = hash_func
        self.mgf = mgf
        self.hlen = hash_func().digest_size
        self.salt_len = salt_len if salt_len is not None else self.hlen

    def encode(self, m_hash: bytes, em_bits: int) -> bytes:
        """Mã hóa PSS theo RFC 8017"""
        em_len = (em_bits + 7) // 8
        if len(m_hash) != self.hlen:
            raise ValueError("Invalid hash length")
        if em_len < self.hlen + self.salt_len + 2:
            raise ValueError("Encoding error")

        # Bước 1: Tạo salt
        salt = os.urandom(self.salt_len)

        # Bước 2-3: Tạo M' và H
        m_prime = b'\x00' * 8 + m_hash + salt
        h = self.hash_func(m_prime).digest()

        # Bước 4-6: Tạo maskedDB
        ps_len = em_len - self.salt_len - self.hlen - 2
        db = b'\x00' * ps_len + b'\x01' + salt
        db_mask = self.mgf(h, em_len - self.hlen - 1, self.hash_func)
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

        # Bước 7: Clear leftmost bits
        if 8 * em_len - em_bits > 0:
            mask = 0xFF >> (8 * em_len - em_bits)
            masked_db = bytes([masked_db[0] & mask]) + masked_db[1:]

        # Bước 8: Kết hợp EM
        em = masked_db + h + b'\xbc'
        return em

    def decode(self, em: bytes, em_bits: int, m_hash: bytes) -> bool:
        """Giải mã và xác minh PSS"""
        em_len = (em_bits + 7) // 8
        if len(em) != em_len or em[-1] != 0xbc:
            return False

        masked_db = em[:em_len - self.hlen - 1]
        h = em[em_len - self.hlen - 1:-1]

        # Kiểm tra leftmost bits
        if 8 * em_len - em_bits > 0:
            if masked_db[0] >> (8 - (8 * em_len - em_bits)) != 0:
                return False

        db_mask = self.mgf(h, em_len - self.hlen - 1, self.hash_func)
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

        # Tách salt
        try:
            sep_idx = db.index(b'\x01', em_len - self.hlen - self.salt_len - 2)
        except ValueError:
            return False

        salt = db[sep_idx + 1:]
        m_prime = b'\x00' * 8 + m_hash + salt
        h_prime = self.hash_func(m_prime).digest()
        return h_prime == h

    def sign(self, message: bytes, rsa_key) -> int:
        """Ký với PSS"""
        m_hash = self.hash_func(message).digest()
        k = rsa_key.public["n"].bit_length()
        em = self.encode(m_hash, k - 1)
        m_int = int.from_bytes(em, "big")
        return rsa_key.decrypt_int(m_int)

    def verify(self, message: bytes, signature: int, rsa_key) -> bool:
        """Xác minh chữ ký PSS"""
        k = rsa_key.public["n"].bit_length()
        em_len = (k + 7) // 8
        s_int = rsa_key.encrypt_int(signature)
        em = s_int.to_bytes(em_len, "big")
        m_hash = self.hash_func(message).digest()
        return self.decode(em, k - 1, m_hash)


class RSASSA_PKCS1v15:
    """Chế độ cũ (chỉ dùng khi tương thích bắt buộc)"""
    ASN1_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")

    @staticmethod
    def sign(message: bytes, rsa_key) -> int:
        k = (rsa_key.public["n"].bit_length() + 7) // 8
        hash_val = hashlib.sha256(message).digest()
        t = RSASSA_PKCS1v15.ASN1_SHA256 + hash_val

        if len(t) > k - 11:
            raise ValueError("Message too long")

        ps = b"\xff" * (k - len(t) - 3)
        em = b"\x00\x01" + ps + b"\x00" + t
        m_int = int.from_bytes(em, "big")
        return rsa_key.decrypt_int(m_int)

    @staticmethod
    def verify(message: bytes, signature: int, rsa_key) -> bool:
        k = (rsa_key.public["n"].bit_length() + 7) // 8
        em = rsa_key.encrypt_int(signature).to_bytes(k, "big")
        if not em.startswith(b"\x00\x01"):
            return False
        try:
            sep = em.index(b"\x00", 2)
        except ValueError:
            return False
        t = em[sep + 1:]
        hash_val = hashlib.sha256(message).digest()
        return t == RSASSA_PKCS1v15.ASN1_SHA256 + hash_val