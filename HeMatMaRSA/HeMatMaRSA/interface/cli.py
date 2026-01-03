# interface/cli.py
import sys

# --- IMPORT MODULES ---
from utils import converters, key_io, hash_utils

# Lưu ý: Python cần chạy từ main.py ở thư mục gốc mới hiểu dòng này
from core.rsa_core import RSAKeyPair
from core.signature import RSASSA_PSS

def load_key_into_core(filename, is_private=False):
    # 1. Dùng tool của B để đọc file lấy số (exponent, modulus)
    key_tuple = key_io.load_key(filename)
    if not key_tuple:
        return None

    exponent, n = key_tuple

    # 2. Tạo object rỗng của A
    rsa_obj = RSAKeyPair()

    # 3. Nhồi dữ liệu vào đúng chỗ mà core A yêu cầu
    if is_private:
        # Core A cần dict {'d': ..., 'n': ...}
        rsa_obj.private = {"d": exponent, "n": n}
        # Lưu ý: Vì file PEM chỉ lưu d và n, nên sẽ thiếu p, q.
        # Core A sẽ tự động chuyển sang chế độ giải mã chậm (không CRT), không sao cả.
        rsa_obj.public = {"n": n}
    else:
        # Core A cần dict {'e': ..., 'n': ...}
        rsa_obj.public = {"e": exponent, "n": n}

    return rsa_obj

def run_app():
    print("========================================")
    print("   HỆ THỐNG MÃ HÓA RSA - NHÓM A & B")
    print("========================================")

    while True:
        print("\n--- MENU CHÍNH ---")
        print("1. Sinh cặp khóa mới (Generate Keys)")
        print("2. Mã hóa tin nhắn (Encrypt)")
        print("3. Giải mã tin nhắn (Decrypt)")
        print("4. Ký số văn bản (Sign)")
        print("5. Xác thực chữ ký (Verify)")
        print("0. Thoát")

        choice = input(">> Chọn chức năng (0-5): ")

        if choice == '1':
            print("\n[1] SINH KHÓA MỚI")
            try:
                bits = int(input("Nhập độ dài bit (khuyên dùng 1024 trở lên): "))
                print(f"Đang tính toán sinh khóa {bits}-bit (Sẽ mất vài giây)...")

                # Gọi Core A để tính toán
                rsa = RSAKeyPair()
                rsa.generate(bits)

                # Lưu Public Key (e, n)
                key_io.save_key((rsa.public['e'], rsa.public['n']), "public.pem", is_private=False)

                # Lưu Private Key (d, n)
                # (Chỉ lưu d và n cho đơn giản, bỏ qua p,q)
                key_io.save_key((rsa.private['d'], rsa.private['n']), "private.pem", is_private=True)

                print("=> Đã sinh và lưu khóa thành công!")
            except Exception as e:
                print(f"Lỗi: {e}")

        elif choice == '2':
            print("\n[2] MÃ HÓA (ENCRYPT)")
            msg = input("Nhập tin nhắn cần gửi: ")
            key_file = "public.pem"

            # Nạp khóa
            rsa = load_key_into_core(key_file, is_private=False)
            if rsa:
                # B1: Chuyển Text -> Số (Utils B)
                m_int = converters.text_to_int(msg)
                print(f"-> Bản rõ dạng số: {m_int}")

                # B2: Mã hóa (Core A)
                try:
                    c_int = rsa.encrypt_int(m_int)
                    print(f"-> BẢN MÃ (Ciphertext): {c_int}")
                    print("(Hãy copy số này gửi cho người nhận)")
                except ValueError as ve:
                    print(f"Lỗi: {ve} (Tin nhắn quá dài so với khóa!)")

        elif choice == '3':
            print("\n[3] GIẢI MÃ (DECRYPT)")
            try:
                c_input = input("Nhập bản mã (số nguyên): ")
                c_int = int(c_input)
                key_file =  "private.pem"

                # Nạp khóa
                rsa = load_key_into_core(key_file, is_private=True)
                if rsa:
                    # B1: Giải mã (Core A)
                    print("Đang giải mã...")
                    m_int = rsa.decrypt_int(c_int, use_crt=False) # Tắt CRT vì file PEM thiếu p,q

                    # B2: Chuyển Số -> Text (Utils B)
                    msg = converters.int_to_text(m_int)
                    print(f"-> NỘI DUNG GỐC: {msg}")
            except Exception as e:
                print(f"Giải mã thất bại: {e}")

        elif choice == '4':
            print("\n[4] KÝ SỐ (SIGN)")
            msg = input("Nhập văn bản cần ký: ")
            key_file = "private.pem"

            rsa = load_key_into_core(key_file, is_private=True)
            if rsa:
                # Dùng module Signature của A
                signer = RSASSA_PSS()
                # Chuyển string sang bytes để ký
                msg_bytes = msg.encode('utf-8')

                signature = signer.sign(msg_bytes, rsa)
                print(f"-> CHỮ KÝ SỐ ĐƯỢC TẠO: {signature}")

        elif choice == '5':
            print("\n[5] XÁC THỰC CHỮ KÝ (VERIFY)")
            msg = input("Nhập văn bản gốc: ")
            sig_input = input("Nhập chữ ký số (Integer): ")
            key_file = "public.pem"

            rsa = load_key_into_core(key_file, is_private=False)
            if rsa:
                try:
                    sig_int = int(sig_input)
                    signer = RSASSA_PSS()
                    msg_bytes = msg.encode('utf-8')

                    is_valid = signer.verify(msg_bytes, sig_int, rsa)

                    if is_valid:
                        print("=> KẾT QUẢ: ✅ CHỮ KÝ HỢP LỆ (Văn bản nguyên vẹn)")
                    else:
                        print("=> KẾT QUẢ: ❌ CHỮ KÝ KHÔNG HỢP LỆ (Văn bản đã bị sửa hoặc sai khóa)")
                except Exception as e:
                    print(f"Lỗi xác thực: {e}")

        elif choice == '0':
            print("Tạm biệt!")
            sys.exit()
        else:
            print("Lựa chọn không hợp lệ.")
