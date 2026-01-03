# RSA_Miller_Rabin
Dự án mã hóa RSA hoàn chỉnh kết hợp lõi toán học mạnh (Nhóm A) với giao diện thực tiễn (Nhóm B).  
Chức năng chính:
Sinh khóa RSA: Từ 512-bit đến 4096-bit, hỗ trợ strong prime

Mã hóa/Giải mã: Với padding OAEP (SHA-256) an toàn

Chữ ký số: Cả PSS (hiện đại) và PKCS#1 v1.5 (tương thích)

Giao diện CLI: Menu tương tác trực quan

Quản lý khóa: Đọc/ghi file PEM đơn giản

Điểm nổi bật:
🔒 Bảo mật: CSPRNG, Miller-Rabin 40 vòng, OAEP padding
⚡ Hiệu năng: Hỗ trợ CRT tăng tốc giải mã 4x
🛠️ Linh hoạt: Kiến trúc module, dễ tích hợp và mở rộng
🧪 Đáng tin cậy: Bộ kiểm thử đầy đủ với vector NIST

Công nghệ:
Python 3.13 + gmpy2 xử lý số lớn

hashlib (SHA-256), secrets module

Kiến trúc hướng module rõ ràng

Ứng dụng: Giáo dục mã hóa, prototype hệ thống PKI, demo bảo mật trong thực tế.
