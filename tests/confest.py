# tests/conftest.py
import sys
from pathlib import Path

# Tự động thêm thư mục gốc của project vào đường dẫn tìm kiếm module của Python
root_dir = Path(__file__).parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))