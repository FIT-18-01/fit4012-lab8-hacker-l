import os
import socket
from pathlib import Path
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad
import secure_transfer_utils as utils

SERVER_IP = os.getenv("SERVER_IP", "192.168.61.170") # IP máy của bạn
DATA_PORT = int(os.getenv("DATA_PORT", os.getenv("PORT", "6000")))
SENDER_PRIVATE_KEY_PATH = os.getenv("SENDER_PRIVATE_KEY", "keys/sender_private.pem")
MESSAGE_ENV = os.getenv("MESSAGE")
INPUT_FILE = os.getenv("INPUT_FILE", "")

def get_plaintext() -> bytes:
    if INPUT_FILE:
        return Path(INPUT_FILE).read_bytes()
    if MESSAGE_ENV is not None:
        return MESSAGE_ENV.encode("utf-8")
    return input("Nhập bản tin P: ").encode("utf-8")

def main() -> None:
    plaintext = get_plaintext()
    
    # 1. Tải Private Key của Sender để ký số
    if not Path(SENDER_PRIVATE_KEY_PATH).exists():
        print(f"[-] Không tìm thấy file khóa bí mật sender: {SENDER_PRIVATE_KEY_PATH}")
        return
    sender_private_key = utils.load_private_key(SENDER_PRIVATE_KEY_PATH)
    
    # 2. Tạo bản băm SHA-256 theo chuẩn chữ ký số
    hash_obj = SHA256.new(plaintext)
    plaintext_hash = hash_obj.digest()
    
    # 3. KÝ SỐ: Dùng Private Key của Sender để ký lên bản băm (Độ dài chữ ký luôn là 256 bytes)
    signature = pkcs1_15.new(sender_private_key).sign(hash_obj)
    
    # 4. Mã hóa bản tin P bằng DES-CBC
    des_key, iv = utils.generate_des_key_iv()
    cipher_des = DES.new(des_key, DES.MODE_CBC, iv)
    encrypted_body = cipher_des.encrypt(pad(plaintext, 8))
    ciphertext_with_iv = iv + encrypted_body

    # 5. Đóng gói gói tin: Gửi khóa DES, Ciphertext và Chữ ký số (256 bytes) ở cuối
    packet = (
        utils.pack_length(des_key)
        + des_key
        + utils.pack_length(ciphertext_with_iv)
        + ciphertext_with_iv
        + signature
    )

    # 6. Gửi qua socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(300)
        sock.connect((SERVER_IP, DATA_PORT))
        sock.sendall(packet)

    print("[+] Đã ký số và gửi gói tin bảo mật thành công!")
    print(f"    - SHA-256 (Bản băm gốc): {plaintext_hash.hex()}")

if __name__ == "__main__":
    main()