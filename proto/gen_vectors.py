"""Sinh test_vectors.json để firmware C (và server của Hoàng) so khớp từng byte.

Khóa ở đây là KHÓA THỬ NGHIỆM CỐ ĐỊNH, ai cũng biết. Chỉ dùng để kiểm thử.
Mọi thứ đều xác định (nonce cố định, ký RFC 6979) nên chạy nhiều lần ra cùng một file.
"""
import json
import os
import unicodedata

from common import (GET_PUBKEY, SIGN_REQUEST, bank_message, device_message, key_id,
                    make_frame, public_key, sha256, sign, encode_slip)
from device import Device, Flash, Screen

BANK_PRIV = sha256(b"TEST ONLY - bank key - do not use")
DEVICE_PRIV = sha256(b"TEST ONLY - device key - do not use")
PIN = "123456"
START_COUNTER = 41          # counter đang lưu trong flash; lần ký kế tiếp dùng 42
NAME_64 = "CÔNG TY TNHH ĐẦU TƯ VÀ PHÁT TRIỂN "    # biên: tên đúng 64 byte (SPEC §3)
NAME_64 += "A" * (64 - len(NAME_64.encode("utf-8")))
assert len(NAME_64.encode("utf-8")) == 64


class AlwaysApprove:
    """Người dùng luôn đồng ý và nhập đúng PIN."""
    def approve(self):
        return True

    def read_pin(self):
        return PIN


def make_device():
    flash = Flash({"key": DEVICE_PRIV, "counter": START_COUNTER, "pin": PIN, "pin_fails": 0})
    return Device(flash, Screen(), AlwaysApprove(), public_key(BANK_PRIV))


def raw_slip(nonce, amount, account_bytes, name_bytes):
    """Ghép phiếu bằng tay, không kiểm tra gì: để tạo phiếu sai cố ý."""
    return (nonce + amount.to_bytes(8, "big") + bytes([len(account_bytes)]) + account_bytes
            + bytes([len(name_bytes)]) + name_bytes)


def main():
    device = make_device()
    bank_pub = public_key(BANK_PRIV)
    device_pub = public_key(DEVICE_PRIV)
    out = {
        "note": "KHÓA THỬ NGHIỆM, công khai. Chỉ dùng để kiểm thử. Mọi giá trị nhị phân là hex.",
        "spec_version": "0.3",
        "bank_priv": BANK_PRIV.hex(),
        "bank_pub": bank_pub.hex(),
        "device_priv": DEVICE_PRIV.hex(),
        "device_pub": device_pub.hex(),
        "device_key_id": key_id(device_pub).hex(),
        "valid_slips": [],
        "reject_slips": [],
        "frames": [],
    }

    # ---- Phiếu hợp lệ: đi trọn quy trình qua thiết bị giả lập ----
    valid = [
        (bytes(range(16)), 1_500_000, "0123456789", "NGUYỄN VĂN AN"),
        (bytes([0xA5] * 16), 2**64 - 1, "1234567890123456789", "Trần Thị Thu Hương"),  # biên: số tiền lớn nhất, TK 19 số
        (bytes([0xFF] * 16), 1, "7", "LÊ"),                                              # biên: ngắn nhất
        (bytes([0x5A] * 16), 2_000_000, "0123456789", NAME_64),                         # biên: tên đúng 64 byte
    ]
    for nonce, amount, account, name in valid:
        slip = encode_slip(nonce, amount, account, name)
        bank_sig = sign(BANK_PRIV, bank_message(slip))
        request = make_frame(SIGN_REQUEST, slip + bank_sig)
        response = device.handle_frame(request)
        counter = device.flash.read("counter")
        assert response[3] == 0, "thiết bị phải đồng ý phiếu hợp lệ"
        out["valid_slips"].append({
            "nonce": nonce.hex(), "amount": amount, "to_account": account,
            "to_name": name, "to_name_utf8": name.encode("utf-8").hex(),
            "slip": slip.hex(),
            "bank_message": bank_message(slip).hex(),
            "bank_hash": sha256(bank_message(slip)).hex(),
            "bank_sig": bank_sig.hex(),
            "counter": counter,
            "device_message": device_message(slip, counter).hex(),
            "device_hash": sha256(device_message(slip, counter)).hex(),
            "device_sig": response[3 + 5:].hex(),
            "sign_request_frame": request.hex(),
            "sign_result_frame": response.hex(),
        })

    # ---- Phiếu sai định dạng: CÓ chữ ký ngân hàng đúng, nên thiết bị qua được bước kiểm tra
    #      chữ ký và phải từ chối ở bước giải mã, trả status 3. ----
    nonce = bytes(range(16))
    good = raw_slip(nonce, 1_500_000, b"0123456789", "NGUYỄN VĂN AN".encode())
    nfd_name = unicodedata.normalize("NFD", "NGUYỄN VĂN AN").encode()
    reject = [
        ("to_name có dấu kết hợp (dạng NFD)", raw_slip(nonce, 1_500_000, b"0123456789", nfd_name)),
        ("thừa 1 byte cuối", good + b"\x00"),
        ("thiếu 1 byte cuối", good[:-1]),
        ("thiếu byte độ dài tên", raw_slip(nonce, 1_500_000, b"0123456789", b"")[:-1]),
        ("to_account có chữ cái", raw_slip(nonce, 1_500_000, b"01234A6789", b"AN")),
        ("to_account 20 chữ số", raw_slip(nonce, 1_500_000, b"1" * 20, b"AN")),
        ("to_account rỗng", raw_slip(nonce, 1_500_000, b"", b"AN")),
        ("to_name rỗng", raw_slip(nonce, 1_500_000, b"0123456789", b"")),
        ("to_name 65 byte", raw_slip(nonce, 1_500_000, b"0123456789", b"A" * 65)),
        ("to_name có xuống dòng", raw_slip(nonce, 1_500_000, b"0123456789", "NGUYỄN\nVĂN AN".encode())),
        ("số tiền bằng 0", raw_slip(nonce, 0, b"0123456789", "NGUYỄN VĂN AN".encode())),
        ("to_name không phải UTF-8", raw_slip(nonce, 1_500_000, b"0123456789", b"\xc3\x28")),
    ]
    for reason, slip in reject:
        bank_sig = sign(BANK_PRIV, bank_message(slip))
        request = make_frame(SIGN_REQUEST, slip + bank_sig)
        response = device.handle_frame(request)
        assert response[3] == 3, reason
        out["reject_slips"].append({"reason": reason, "slip": slip.hex(), "bank_sig": bank_sig.hex(),
                                    "sign_request_frame": request.hex(),
                                    "expected_response": response.hex()})

    # ---- Khung USB mẫu và phản hồi mong đợi ----
    good_request = bytes.fromhex(out["valid_slips"][0]["sign_request_frame"])
    bad_sig = bytearray(good_request)
    bad_sig[-1] ^= 0x01
    tampered = bytearray(good_request)
    tampered[3 + 16 + 7] ^= 0x01                      # đổi 1 bit của số tiền
    frames = [
        ("GET_PUBKEY", make_frame(GET_PUBKEY, b"")),
        ("SIGN_REQUEST, sai 1 bit chữ ký ngân hàng → status 2", bytes(bad_sig)),
        ("SIGN_REQUEST, sửa số tiền → status 2", bytes(tampered)),
        ("khung rỗng → status 3", b""),
        ("LEN lớn hơn dữ liệu thực → status 3", b"\x02\x00\x10" + bytes(5)),
        ("LEN = 513 → status 3", b"\x02\x02\x01" + bytes(513)),
        ("TYPE không hợp lệ → status 3", make_frame(0x7F, b"abc")),
        ("GET_PUBKEY có payload → status 3", make_frame(GET_PUBKEY, b"x")),
        ("SIGN_REQUEST chỉ có 64 byte → status 3", make_frame(SIGN_REQUEST, bytes(64))),
    ]
    for name, request in frames:
        out["frames"].append({"name": name, "request": request.hex(),
                              "expected_response": device.handle_frame(request).hex()})

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_vectors.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("Đã ghi", path)


if __name__ == "__main__":
    main()
