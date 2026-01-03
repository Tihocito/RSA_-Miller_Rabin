# Chuyển chữ sang số và ngược lại.

def text_to_int(text: str) -> int:
    text_bytes = text.encode()
    number = int.from_bytes(text_bytes, byteorder='big')
    return number

def int_to_text(number: int) -> str:
    try:
        num_bytes = (number.bit_length() + 7) // 8
        text_bytes = number.to_bytes(num_bytes, byteorder='big')
        return text_bytes.decode()

    except Exception as e:
        print(f"Không thể giải mã số thành văn bản: {e}")
        return "[Error: Decode Failed]"

# if __name__ == "__main__":
#     print("--- ĐANG TEST MODULE CONVERTERS ---")
#     original_msg = "Hello RSA Team B!"
#     print(f"1. Tin nhắn gốc: {original_msg}")
#
#     num = text_to_int(original_msg)
#     print(f"2. Chuyển thành số nguyên (Int): {num}")

    # recovered_msg = int_to_text(num)
    # print(f"3. Khôi phục lại tin nhắn: {recovered_msg}")
    #
    # if original_msg == recovered_msg:
    #     print("=> KẾT QUẢ: THÀNH CÔNG! (Text <-> Int chuẩn)")
    # else:
    #     print("=> KẾT QUẢ: THẤT BẠI! (Có lỗi xảy ra)")
