# main.py
import sys
import os

# Thêm đường dẫn hiện tại vào hệ thống để Python tìm được các thư mục con
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from interface.cli import run_app

if __name__ == "__main__":
    try:
        run_app()
    except KeyboardInterrupt:
        print("\nĐã dừng chương trình.")

