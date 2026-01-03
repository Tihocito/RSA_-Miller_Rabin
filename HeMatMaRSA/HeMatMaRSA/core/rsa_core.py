# core/rsa_core.py
"""
Lõi RSA với CRT
"""

import time
from .math_utils import gcd, mod_inverse, mod_pow
from .prime_gen import generate_prime


class RSAKeyPair:
    def __init__(self):
        self.public = {}
        self.private = {}
        self.generated_at = None

    def generate(self, bits=4096):
        # CHỈNH SỬA: Cho phép từ 512-bit trở lên để test
        assert bits >= 512, "Độ dài khóa quá nhỏ"
        half = bits // 2

        p = generate_prime(half)
        q = generate_prime(half)
        while abs(p - q) < (1 << (half // 2)):
            q = generate_prime(half)

        n = p * q
        phi = (p - 1) * (q - 1)

        e = 65537
        if gcd(e, phi) != 1:
            raise RuntimeError("e và φ(n) không nguyên tố cùng nhau")

        d = mod_inverse(e, phi)

        self.public = {"n": n, "e": e}
        self.private = {"n": n, "d": d, "p": p, "q": q}
        self.generated_at = time.time()

        return self

    def encrypt_int(self, m: int) -> int:
        """Mã hóa số nguyên"""
        if m < 0 or m >= self.public.get("n", 1 << 2048):
            raise ValueError("Plaintext nằm ngoài khoảng [0, n)")
        return pow(m, self.public["e"], self.public["n"])

    def decrypt_int(self, c: int, use_crt: bool = True) -> int:
        """Giải mã với CRT"""
        # CHỈNH SỬA: Kiểm tra xem có p và q không
        if "p" not in self.private or "q" not in self.private:
            use_crt = False
        
        if c < 0 or c >= self.private["n"]:
            raise ValueError("Ciphertext nằm ngoài khoảng [0, n)")

        if not use_crt:
            return pow(c, self.private["d"], self.private["n"])

        p, q, d = self.private["p"], self.private["q"], self.private["d"]
        dp = d % (p - 1)
        dq = d % (q - 1)
        qinv = mod_inverse(q, p)

        m1 = pow(c % p, dp, p)
        m2 = pow(c % q, dq, q)
        h = (qinv * (m1 - m2)) % p
        return m2 + h * q