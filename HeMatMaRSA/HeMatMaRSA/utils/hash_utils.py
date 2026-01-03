# Hàm băm SHA.

import hashlib

def hash_sha256(data: str) -> int:

    data_bytes = data.encode()
    hash_object = hashlib.sha256(data_bytes)
    hex_dig = hash_object.hexdigest()
    return int(hex_dig, 16)

# --- TEST NHANH ---
if __name__ == "__main__":
    text = "Hello"
    print(f"Văn bản: {text}")
    print(f"Mã băm (Integer): {hash_sha256(text)}")
