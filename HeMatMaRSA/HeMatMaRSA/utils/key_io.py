# Lưu/đọc file khóa.

import base64
import os

def save_key(key_tuple, filename, is_private=False):
    """Lưu key vào file theo định dạng PEM"""
    # 1. Xác định Header/Footer
    key_type = "PRIVATE" if is_private else "PUBLIC"
    header = f"-----BEGIN RSA {key_type} KEY-----"
    footer = f"-----END RSA {key_type} KEY-----"

    # 2. Ghép và mã hóa nội dung
    raw_content = f"{key_tuple[0]}:{key_tuple[1]}"
    b64_str = base64.b64encode(raw_content.encode('utf-8')).decode('utf-8')

    # 3. Ghi ra file (Đã sửa: Ghi đầy đủ Header - Nội dung - Footer)
    with open(filename, 'w') as f:
        f.write(header + "\n")
        f.write(b64_str + "\n")
        f.write(footer)

    print(f"[KeyIO] Đã lưu khóa vào file: {os.path.abspath(filename)}")

def load_key(filename):
    """Đọc file PEM và trả về (exponent, modulus)"""
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()

        data_str = ""
        for line in lines:
            # Bỏ qua các dòng header/footer để lấy chuỗi base64 sạch
            if "-----" not in line:
                data_str += line.strip()

        decoded_bytes = base64.b64decode(data_str)
        decoded_str = decoded_bytes.decode('utf-8')

        parts = decoded_str.split(':')
        return int(parts[0]), int(parts[1])

    except Exception as e:
        print(f"[Lỗi KeyIO] Không đọc được file {filename}: {e}")
        return None

# --- TEST NHANH ---
if __name__ == "__main__":
    dummy_key = (65537, 999999999)

    # Thử đọc lại (Đã sửa lỗi thụt đầu dòng ở đây)
    loaded_key = load_key("test_key.pem")

    print(f"Khóa gốc: {dummy_key}")
    print(f"Khóa đọc : {loaded_key}")

    if dummy_key == loaded_key:
        print("=> KẾT QUẢ: THÀNH CÔNG!")
