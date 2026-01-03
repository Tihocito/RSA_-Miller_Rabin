# core/prime_gen.py
"""
Sinh số nguyên tố lớn (với tùy chọn strong prime)
"""

import secrets
from .math_utils import is_probably_prime


def generate_prime(bits: int, strong: bool = False):
    """Sinh số nguyên tố bits-bit, có thể dùng strong prime"""
    assert bits >= 512, "Prime quá nhỏ"

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << bits - 1) | 1  # Đặt bit đầu và cuối = 1

        if strong and bits >= 1024:
            # Kiểm tra strong prime: (p-1) và (p+1) có ước nguyên tố lớn
            if not is_probably_prime(candidate):
                continue
            # Kiểm tra (candidate-1)/2 cũng là nguyên tố
            if not is_probably_prime((candidate - 1) // 2):
                continue
            # Kiểm tra (candidate+1)/2 cũng là nguyên tố
            if not is_probably_prime((candidate + 1) // 2):
                continue
            return candidate
        else:
            if is_probably_prime(candidate):
                return candidate