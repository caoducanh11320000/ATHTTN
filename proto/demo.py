"""Chạy quy trình đầy đủ và 11 tình huống tấn công (bảng "Điều kiện hoàn thành bước 2" trong CLAUDE.md).

Trình duyệt KHÔNG tin cậy (SPEC §1): mô phỏng bằng các hàm relay. Hàm trung thực chuyển nguyên
dữ liệu; hàm của mã độc sửa dữ liệu theo ý kẻ gian.
"""
import random

from bank import EXPIRY_SECONDS, Bank
from common import (GET_PUBKEY, PUBKEY, SIGN_REQUEST, STATUS_BAD_BANK_SIG, STATUS_BAD_FORMAT,
                    STATUS_REJECTED, make_frame, new_private_key, parse_frame, public_key)
from device import MAX_PIN_FAILS, Device, Flash, Screen, format_vnd

VICTIM = ("0123456789", "NGUYỄN VĂN AN")        # người nhận thật
ATTACKER = ("9704123456789012", "PHẠM THỊ HỒNG")   # tài khoản của kẻ gian


class Clock:
    def __init__(self):
        self.t = 1_000_000.0

    def time(self):
        return self.t


class SimUser:
    """Người dùng giả lập, đóng vai 2 nút nhấn. Đồng ý khi màn hình hiện đúng thứ mình định chuyển."""
    def __init__(self, screen, pin):
        self.screen = screen
        self.pin = pin
        self.expect = []

    def intend(self, amount, account, name):
        self.expect = ["Số tiền: " + format_vnd(amount), "Tới TK: " + account, "Tên: " + name]

    def approve(self):
        for line in self.expect:
            if line not in self.screen.lines:
                return False
        return True

    def read_pin(self):
        return self.pin


def new_device(bank_pub, pin="123456"):
    screen = Screen()
    user = SimUser(screen, pin)
    device = Device(Flash(), screen, user, bank_pub)
    device.boot()
    return device, user


# ---------- Trình duyệt ----------

def honest(frame):
    return frame


def browser_pay(bank, device, customer, amount, to_account, to_device=honest, to_bank=honest):
    """Một lần chuyển tiền: ngân hàng → trình duyệt → thiết bị → trình duyệt → ngân hàng.
    Trả (kết quả của ngân hàng, nonce, payload SIGN_RESULT) để các tình huống dùng lại."""
    slip, bank_sig = bank.create_transaction(customer, amount, to_account)
    request = to_device(make_frame(SIGN_REQUEST, slip + bank_sig))
    response = to_bank(device.handle_frame(request))
    nonce = parse_frame(request)[1][:16]
    payload = parse_frame(response)[1]
    return bank.process_result(nonce, payload), nonce, payload


# Mã độc: sửa số tiền trong phiếu trước khi xuống thiết bị (tình huống 3).
def tamper_amount(frame):
    f = bytearray(frame)
    f[3 + 16:3 + 24] = (99_000_000).to_bytes(8, "big")   # 3 byte đầu khung, 16 byte nonce
    return bytes(f)


# Mã độc: tăng counter trong kết quả gửi về ngân hàng (tình huống 5).
def tamper_counter(frame):
    f = bytearray(frame)
    counter = int.from_bytes(f[4:8], "big")              # 3 byte đầu khung, 1 byte status
    f[4:8] = (counter + 1000).to_bytes(4, "big")
    return bytes(f)


# ---------- Các tình huống ----------

passed = 0


def check(n, title, expected, actual):
    global passed
    ok = expected == actual
    passed += ok
    print(f"[{'ĐÚNG' if ok else 'SAI '}] {n:2}. {title}\n         kỳ vọng: {expected} | thực tế: {actual}")


def main():
    clock = Clock()
    bank_priv = new_private_key()
    bank = Bank(bank_priv, now=clock.time)
    bank_pub = public_key(bank_priv)
    bank.names = {VICTIM[0]: VICTIM[1], ATTACKER[0]: ATTACKER[1]}

    # 1. Đăng ký (R7): ngân hàng lấy DK_pub qua USB trong môi trường tin cậy, hai bên so mã.
    device, user = new_device(bank_pub)
    shown_id = device.screen.lines[1]
    pub = parse_frame(device.handle_frame(make_frame(GET_PUBKEY, b"")))[1]
    bank_id = bank.register_device("alice", pub).hex()
    check(1, "Đăng ký, so mã nhận dạng khóa (R7)", "khớp",
          "khớp" if shown_id == bank_id else f"{shown_id} ≠ {bank_id}")

    # 2. Giao dịch bình thường.
    user.intend(1_500_000, *VICTIM)
    result, good_nonce, good_payload = browser_pay(bank, device, "alice", 1_500_000, VICTIM[0])
    check(2, "Giao dịch bình thường", "ok", result)

    # 3. Mã độc sửa số tiền → chữ ký ngân hàng không còn khớp (R2).
    user.intend(500_000, *VICTIM)
    _, _, payload = browser_pay(bank, device, "alice", 500_000, VICTIM[0], to_device=tamper_amount)
    check(3, "Mã độc sửa số tiền trước khi xuống thiết bị (R2)", STATUS_BAD_BANK_SIG, payload[0])

    # 4. Mã độc xin ngân hàng một giao dịch THẬT tới kẻ gian rồi tráo phiếu.
    #    Chữ ký ngân hàng đúng, nhưng màn hình hiện tên kẻ gian do ngân hàng tra → người dùng từ chối (R3).
    def swap_slip(frame):
        slip, sig = bank.create_transaction("alice", 500_000, ATTACKER[0])
        return make_frame(SIGN_REQUEST, slip + sig)
    user.intend(500_000, *VICTIM)
    result, _, payload = browser_pay(bank, device, "alice", 500_000, VICTIM[0], to_device=swap_slip)
    check(4, "Mã độc tráo phiếu bằng giao dịch thật tới kẻ gian (R3)",
          (STATUS_REJECTED, "status"), (payload[0], result))

    # 5. Mã độc sửa counter trong kết quả → chữ ký thiết bị sai (R4).
    user.intend(200_000, *VICTIM)
    result, _, _ = browser_pay(bank, device, "alice", 200_000, VICTIM[0], to_bank=tamper_counter)
    check(5, "Mã độc sửa counter trong kết quả (R4)", "signature", result)

    # 6. Phát lại kết quả của tình huống 2 (R5).
    check(6, "Phát lại kết quả cũ (R5)", "nonce", bank.process_result(good_nonce, good_payload))

    # 7. Dùng (counter, chữ ký) cũ cho giao dịch mới (R4, R6).
    #    Chữ ký cũ phủ phiếu cũ, không khớp phiếu mới → sai chữ ký, dù giữ hay tăng counter.
    #    Thiết bị KHÔNG bị khóa: dữ liệu giả không được phép khóa thiết bị của nạn nhân.
    slip, _ = bank.create_transaction("alice", 9_000_000, VICTIM[0])
    result_a = bank.process_result(slip[:16], good_payload)
    slip, _ = bank.create_transaction("alice", 9_000_000, VICTIM[0])
    old_counter = int.from_bytes(good_payload[1:5], "big")
    bumped = good_payload[:1] + (old_counter + 1).to_bytes(4, "big") + good_payload[5:]
    result_b = bank.process_result(slip[:16], bumped)
    check(7, "Dùng chữ ký cũ cho giao dịch mới (R4, R6)", ("signature", "signature", False),
          (result_a, result_b, bank.devices["alice"]["locked"]))

    # 8. Gửi kết quả sau 200 giây (R5). Thiết bị vẫn ký vì nó không biết giờ; ngân hàng chặn.
    def slow(frame):
        clock.t += 200
        return frame
    user.intend(300_000, *VICTIM)
    result, _, _ = browser_pay(bank, device, "alice", 300_000, VICTIM[0], to_bank=slow)
    check(8, f"Gửi kết quả sau 200 giây (hạn {EXPIRY_SECONDS} s, R5)", "expired", result)

    # 9. Kẻ gian chép flash sang thiết bị khác (R6). Thiết bị thật ký trước, bản sao ký sau
    #    với cùng counter → ngân hàng chặn và khóa thiết bị; sau đó thiết bị thật cũng bị từ chối.
    clone_screen = Screen()
    clone = Device(device.flash.copy(), clone_screen, SimUser(clone_screen, user.pin), bank_pub)
    clone.buttons.intend(7_000_000, *ATTACKER)
    user.intend(100_000, *VICTIM)
    result_real, _, _ = browser_pay(bank, device, "alice", 100_000, VICTIM[0])
    result_clone, _, _ = browser_pay(bank, clone, "alice", 7_000_000, ATTACKER[0])
    user.intend(100_000, *VICTIM)
    result_after, _, _ = browser_pay(bank, device, "alice", 100_000, VICTIM[0])
    check(9, "Bản sao thiết bị (chép flash) ký (R6)", ("ok", "counter", "locked"),
          (result_real, result_clone, result_after))

    # 10. Khung USB rác (R9): thiết bị trả status 3 và không ném lỗi.
    junk = [
        b"",                                          # rỗng
        b"\x02",                                      # thiếu LEN
        b"\x02\x00\x10" + bytes(5),                   # LEN nói 16, thực có 5
        b"\x02\x00\x05" + bytes(16),                  # LEN nói 5, thực có 16
        b"\x02\x02\x01" + bytes(513),                 # LEN = 513 > 512
        make_frame(0x7F, b"abc"),                     # sai loại
        make_frame(0x82, bytes(69)),                  # loại chỉ đi chiều thiết bị → máy
        make_frame(GET_PUBKEY, b"x"),                 # GET_PUBKEY có payload
        make_frame(SIGN_REQUEST, bytes(64)),          # chỉ có chữ ký, không có phiếu
    ]
    statuses = [parse_frame(device.handle_frame(f))[1][0] for f in junk]
    # Thêm 2000 khung ngẫu nhiên: không được ném lỗi, không bao giờ ra status 0.
    rng = random.Random(2026)
    for _ in range(2000):
        f = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
        if rng.random() < 0.5:                        # một nửa có phần đầu khung hợp lệ
            f = make_frame(rng.choice([GET_PUBKEY, SIGN_REQUEST, 0x55]), f)
        ftype, response = parse_frame(device.handle_frame(f))
        # Chấp nhận: PUBKEY (khi trúng GET_PUBKEY rỗng) hoặc SIGN_RESULT chỉ có status khác 0.
        if not (ftype == PUBKEY or (len(response) == 1 and response[0] != 0)):
            statuses.append("lỗi")
    check(10, "Khung USB rác, sai độ dài (R9)", [STATUS_BAD_FORMAT] * len(junk), statuses)

    # 11. Sai PIN 5 lần → khóa bị xóa (R8).
    device2, user2 = new_device(bank_pub, pin="123456")
    bank.register_device("bob", parse_frame(device2.handle_frame(make_frame(GET_PUBKEY, b"")))[1])
    user2.intend(50_000, *VICTIM)
    user2.pin = "000000"
    for _ in range(MAX_PIN_FAILS):
        browser_pay(bank, device2, "bob", 50_000, VICTIM[0])
    user2.pin = "123456"                              # đúng PIN cũng không cứu được nữa
    result, _, payload = browser_pay(bank, device2, "bob", 50_000, VICTIM[0])
    erased = device2.flash.read("key") is None
    check(11, "Sai PIN 5 lần (R8)", ("khóa bị xóa", STATUS_REJECTED),
          ("khóa bị xóa" if erased else "khóa còn", payload[0]))

    print(f"\nKết quả: {passed}/11 tình huống đúng kỳ vọng.")
    print(f"Ngân hàng đã chuyển tiền {len(bank.transfers)} lần (tình huống 2 và thiết bị thật ở 9).")


if __name__ == "__main__":
    main()
