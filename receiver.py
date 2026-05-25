import os
import socket
from pathlib import Path
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import unpad
import secure_transfer_utils as utils

HOST = os.getenv("RECEIVER_HOST", "0.0.0.0")
DATA_PORT = int(os.getenv("DATA_PORT", os.getenv("PORT", "6000")))
SENDER_PUBLIC_KEY_PATH = os.getenv("SENDER_PUBLIC_KEY", "keys/sender_public.pem")

def receive_packet() -> tuple[bytes, bytes, bytes, str]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, DATA_PORT))
        server.listen(1)
        conn, addr = server.accept()

        with conn:
            client_ip = f"{addr[0]}:{addr[1]}"
            print(f"[+] Đã nhận kết nối từ {client_ip}")
            
            # 1. Đọc khóa DES
            enc_key_len_header = utils.recv_exact(conn, 4)
            enc_key_len = utils.parse_length_header(enc_key_len_header)
            des_key = utils.recv_exact(conn, enc_key_len)

            # 2. Đọc bản mã DES 
            cipher_len_header = utils.recv_exact(conn, 4)
            cipher_len = utils.parse_length_header(cipher_len_header)
            ciphertext_with_iv = utils.recv_exact(conn, cipher_len)

            # 3. Đọc chính xác 256 bytes chữ ký số RSA
            signature = utils.recv_exact(conn, 256)
            
            return des_key, ciphertext_with_iv, signature, client_ip

def main() -> None:
    print(f"[*] Receiver đang lắng nghe tại {HOST}:{DATA_PORT}...")

    # 1. Tải Public Key của Sender để xác thực
    if not Path(SENDER_PUBLIC_KEY_PATH).exists():
        print(f"[-] Không tìm thấy file khóa công khai sender tại: {SENDER_PUBLIC_KEY_PATH}")
        return
    sender_public_key = utils.load_public_key(SENDER_PUBLIC_KEY_PATH)

    # 2. Nhận gói tin qua Socket
    des_key, ciphertext_with_iv, signature, client_ip = receive_packet()

    # 3. Giải mã bản tin bằng khóa DES-CBC để lấy lại bản tin gốc P
    iv = ciphertext_with_iv[:8]
    encrypted_body = ciphertext_with_iv[8:]
    cipher_des = DES.new(des_key, DES.MODE_CBC, iv)
    plaintext = unpad(cipher_des.decrypt(encrypted_body), 8)
    message = plaintext.decode("utf-8", errors="replace")

    # 4. Tự tính toán lại bản băm SHA-256 từ bản tin P vừa nhận được
    hash_obj = SHA256.new(plaintext)
    calculated_hash = hash_obj.digest()

    print("\n" + "="*20 + " KẾT QUẢ XÁC THỰC THEO BẢNG " + "="*20)
    print(f"[+] Bản băm tính toán thực tế từ bản tin nhận: {calculated_hash.hex()}")
    
    # 5. Dùng Public Key của Sender để giải mã và đối chiếu trực tiếp chữ ký số với bản băm mới tính
    try:
        pkcs1_15.new(sender_public_key).verify(hash_obj, signature)
        print("[=>] KẾT LUẬN: KHỚP NHAU (=) -> Giải mã Public Key thành công!")
        print("[+] Chữ ký HỢP LỆ, dữ liệu toàn vẹn và đúng người gửi!")
        print(f"[+] Bản tin gốc P nhận được: {message}")
    except (ValueError, TypeError):
        print("[=>] KẾT LUẬN: KHÔNG KHỚP (≠) -> Chữ ký KHÔNG hợp lệ hoặc dữ liệu bị sửa đổi!")
    print("="*69)

if __name__ == "__main__":
    main()