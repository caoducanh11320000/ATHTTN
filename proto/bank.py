"""Phía ngân hàng: đăng ký thiết bị, phát phiếu có chữ ký, xử lý kết quả (SPEC §5, §6, §8)."""
import os
import time

from common import (STATUS_OK, SIG_LEN, bank_message, device_message, encode_slip,
                    key_id, sign, verify)

EXPIRY_SECONDS = 120


class Bank:
    def __init__(self, bank_priv, now=time.time):
        self.priv = bank_priv     # BK, chỉ ngân hàng giữ
        self.now = now            # đồng hồ; demo truyền đồng hồ giả để thử hết hạn
        self.names = {}           # danh bạ: số TK → tên chủ TK (R3)
        self.devices = {}         # khách hàng → {"pub": DK_pub, "counter": counter lớn nhất đã nhận}
        self.txs = {}             # nonce → giao dịch đang chờ xác nhận
        self.transfers = []       # các phiếu đã chuyển tiền

    def register_device(self, customer, device_pub):
        """SPEC §6 (R7): gắn DK_pub với khách hàng. Trả mã nhận dạng để khách so với màn hình thiết bị.
        Giả định DK_pub đến qua kênh đã xác thực (tại quầy)."""
        self.devices[customer] = {"pub": device_pub, "counter": 0, "locked": False}
        return key_id(device_pub)

    def create_transaction(self, customer, amount, to_account):
        """Phát phiếu và ký (R2). Tên người nhận do ngân hàng tra, không lấy từ trình duyệt (R3)."""
        nonce = os.urandom(16)    # R5: mã giao dịch ngẫu nhiên, dùng một lần
        slip = encode_slip(nonce, amount, to_account, self.names[to_account])
        self.txs[nonce] = {"customer": customer, "slip": slip,
                           "time": self.now(), "used": False}
        return slip, sign(self.priv, bank_message(slip))

    def process_result(self, nonce, payload):
        """SPEC §8 (6 bước). payload = status ‖ counter ‖ device_sig (từ SIGN_RESULT).
        Trả "ok" nếu chuyển tiền, ngược lại trả lý do từ chối."""
        # Bước 1 (R5): tìm theo nonce, đánh dấu đã dùng NGAY, trước mọi kiểm tra khác,
        # để một kết quả chỉ được xét đúng một lần dù nó hỏng ở bước nào.
        tx = self.txs.get(nonce)
        if tx is None or tx["used"]:
            return "nonce"
        tx["used"] = True

        # Bước 2 (R5): hạn dùng do ngân hàng kiểm tra; thiết bị không có đồng hồ tin cậy.
        if self.now() - tx["time"] > EXPIRY_SECONDS:
            return "expired"

        # Bước 3: thiết bị không đồng ý thì không có chữ ký.
        if len(payload) < 1 or payload[0] != STATUS_OK:
            return "status"
        if len(payload) != 1 + 4 + SIG_LEN:
            return "format"
        counter = int.from_bytes(payload[1:5], "big")
        device_sig = payload[5:]

        device = self.devices[tx["customer"]]
        # Bước 4: thiết bị đã bị khóa (do phát hiện bản sao trước đó) thì từ chối mọi kết quả.
        if device["locked"]:
            return "locked"

        # Bước 5 (R4): kiểm tra trên phiếu NGÂN HÀNG ĐÃ LƯU, không phải phiếu trình duyệt gửi lại.
        if not verify(device["pub"], device_message(tx["slip"], counter), device_sig):
            return "signature"

        # Bước 6 (R6): chữ ký ĐÚNG mà counter không tăng → có một bản sao khác đang giữ khóa.
        # Khóa thiết bị, cảnh báo khách hàng. Chỉ khóa SAU khi chữ ký đúng: nếu khóa dựa trên
        # dữ liệu chưa xác thực, kẻ gian gửi counter cũ là khóa được thiết bị của nạn nhân.
        if counter <= device["counter"]:
            device["locked"] = True
            return "counter"

        device["counter"] = counter
        self.transfers.append(tx["slip"])
        return "ok"
