# core/oaep.py
"""
OAEP padding (SHA-256)
"""

import hashlib
import os


def mgf1(seed, length, hash_func=hashlib.sha256):
    counter = 0
    output = b""
    while len(output) < length:
        c = counter.to_bytes(4, "big")
        output += hash_func(seed + c).digest()
        counter += 1
    return output[:length]


def oaep_encode(message, k, label=b"", hash_func=hashlib.sha256):
    hlen = hash_func().digest_size
    if len(message) > k - 2 * hlen - 2:
        raise ValueError("Message quá dài")

    lhash = hash_func(label).digest()
    ps = b"\x00" * (k - len(message) - 2 * hlen - 2)
    db = lhash + ps + b"\x01" + message

    seed = os.urandom(hlen)
    db_mask = mgf1(seed, k - hlen - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

    seed_mask = mgf1(masked_db, hlen)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

    return b"\x00" + masked_seed + masked_db


def oaep_decode(em, k, label=b"", hash_func=hashlib.sha256):
    hlen = hash_func().digest_size
    if len(em) != k:
        raise ValueError("EM length error")

    _, masked_seed, masked_db = em[0], em[1:1+hlen], em[1+hlen:]
    seed_mask = mgf1(masked_db, hlen)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

    db_mask = mgf1(seed, k - hlen - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

    lhash = hash_func(label).digest()
    if db[:hlen] != lhash:
        raise ValueError("Label hash mismatch")

    i = db.find(b"\x01", hlen)
    if i == -1:
        raise ValueError("Invalid OAEP padding")

    return db[i+1:]
