"""Thiết bị ký giả lập. Logic ở đây sẽ được chuyển sang C (firmware/).

Ba phần cứng được tách riêng để dễ thay:
  Flash   → NVS của ESP32 (nvs_get_*/nvs_set_*, có NVS encryption)
  Screen  → màn ST7789
  buttons → 2 nút nhấn. Là đối tượng bất kỳ có approve() -> bool và read_pin() -> str.
            Demo dùng người dùng giả lập.
"""
import hmac

from common import (GET_PUBKEY, PUBKEY, SIG_LEN, SIGN_REQUEST, STATUS_BAD_BANK_SIG,
                    STATUS_BAD_FORMAT, STATUS_OK, STATUS_REJECTED, bank_message,
                    decode_slip, device_message, key_id, make_frame, new_private_key,
                    parse_frame, public_key, result_frame, sign, verify)

MAX_PIN_FAILS = 5


class Flash:
    """Bộ nhớ bền: mỗi tên một giá trị. Các tên dùng: key, counter, pin, pin_fails."""
    def __init__(self, data=None):
        self.data = dict(data or {})

    def read(self, name):
        return self.data.get(name)

    def write(self, name, value):
        self.data[name] = value

    def erase(self, name):
        self.data.pop(name, None)

    def copy(self):
        """Tình huống 9: kẻ gian chép nguyên flash sang thiết bị khác."""
        return Flash(self.data)


class Screen:
    def __init__(self):
        self.lines = []

    def show(self, lines):
        self.lines = list(lines)


def format_vnd(amount):
    return f"{amount:,}".replace(",", ".") + " đ"     # 1500000 → "1.500.000 đ"


class Device:
    def __init__(self, flash, screen, buttons, bank_pub):
        self.flash = flash
        self.screen = screen
        self.buttons = buttons
        self.bank_pub = bank_pub      # BK_pub nạp sẵn trong firmware (SPEC §2)

    def boot(self):
        """SPEC §6 (R7): lần đầu chạy thì tự sinh DK (không bao giờ ra khỏi thiết bị) và đặt PIN.
        Luôn hiện mã nhận dạng khóa để người dùng so với ngân hàng."""
        if self.flash.read("key") is None:
            self.flash.write("key", new_private_key())
            self.flash.write("counter", 0)
            self.flash.write("pin_fails", 0)
            self.flash.write("pin", self.buttons.read_pin())
        pub = public_key(self.flash.read("key"))
        self.screen.show(["Mã khóa:", key_id(pub).hex()])

    def handle_frame(self, frame):
        """Nhận một khung USB, trả một khung USB. Không bao giờ ném lỗi với dữ liệu rác (R9)."""
        parsed = parse_frame(frame)
        if parsed is None:
            return result_frame(STATUS_BAD_FORMAT)          # sai độ dài (R9)
        ftype, payload = parsed

        key = self.flash.read("key")
        if key is None:
            return result_frame(STATUS_REJECTED)            # khóa đã bị xóa (R8)

        if ftype == GET_PUBKEY and len(payload) == 0:
            return make_frame(PUBKEY, public_key(key))
        if ftype == SIGN_REQUEST:
            return self.sign_request(key, payload)
        return result_frame(STATUS_BAD_FORMAT)              # sai loại (R9)

    def sign_request(self, key, payload):
        # payload = slip ‖ bank_sig(64)
        if len(payload) <= SIG_LEN:
            return result_frame(STATUS_BAD_FORMAT)
        slip = payload[:-SIG_LEN]
        bank_sig = payload[-SIG_LEN:]

        # R2: kiểm tra chữ ký ngân hàng TRƯỚC, giải mã phiếu SAU.
        # Dữ liệu chưa được xác thực thì không đưa vào bộ giải mã → bớt bề mặt tấn công.
        if not verify(self.bank_pub, bank_message(slip), bank_sig):
            return result_frame(STATUS_BAD_BANK_SIG)
        fields = decode_slip(slip)
        if fields is None:
            return result_frame(STATUS_BAD_FORMAT)          # R1, R9

        # R3: hiện số tiền, số tài khoản, tên; người dùng tự quyết định.
        # Không hiện nonce: người dùng không cần và không kiểm tra được (SPEC §5).
        self.screen.show([
            "Số tiền: " + format_vnd(fields["amount"]),
            "Tới TK: " + fields["to_account"],
            "Tên: " + fields["to_name"],
        ])
        if not self.buttons.approve():
            return result_frame(STATUS_REJECTED)
        if not self.check_pin():
            return result_frame(STATUS_REJECTED)

        # R6: tăng counter và GHI FLASH TRƯỚC KHI KÝ. Nếu mất điện sau khi ký mà chưa ghi,
        # lần sau sẽ ký lại cùng counter → ngân hàng tưởng là bản sao. Ghi trước thì tránh được.
        counter = self.flash.read("counter") + 1
        self.flash.write("counter", counter)
        device_sig = sign(key, device_message(slip, counter))
        return result_frame(STATUS_OK, counter, device_sig)

    def check_pin(self):
        """R8: sai 5 lần thì xóa khóa."""
        entered = self.buttons.read_pin()
        # Tăng số lần sai và GHI FLASH TRƯỚC KHI SO: kẻ gian rút điện ngay khi thấy sai
        # cũng không xóa được lần thử đó.
        fails = self.flash.read("pin_fails") + 1
        self.flash.write("pin_fails", fails)
        # So trong thời gian hằng, không lộ PIN qua thời gian phản hồi.
        if hmac.compare_digest(entered.encode(), self.flash.read("pin").encode()):
            self.flash.write("pin_fails", 0)
            return True
        if fails >= MAX_PIN_FAILS:
            self.flash.erase("key")
        return False
