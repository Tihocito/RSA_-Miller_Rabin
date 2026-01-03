# core/math_utils.py
"""
Toán học nền tảng cho RSA (CSPRNG-safe)
"""

import secrets
import gmpy2
from gmpy2 import mpz


def gcd(a, b):
    return mpz(gmpy2.gcd(a, b))


def mod_inverse(a, m):
    inv = gmpy2.invert(a, m)
    if inv == 0:
        raise ValueError("Không tồn tại nghịch đảo modulo")
    return mpz(inv)


def mod_pow(base, exp, mod):
    return pow(base, exp, mod)


def is_probably_prime(n, rounds=40):
    """
    Miller–Rabin với CSPRNG
    Xác suất sai < 2^-80
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # n − 1 = d · 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
