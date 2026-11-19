"""Phần dùng chung cho cả ngân hàng và thiết bị: mã hóa phiếu, ký/kiểm tra, khung USB.

Mọi hàm nhận và trả bytes/int đơn giản để dễ chuyển sang C.
"""
import hashlib
import unicodedata

from ecdsa import NIST256p, BadSignatureError, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string

# ---------- Hằng số (SPEC §4, §7) ----------
BANK_LABEL = b"BANK-SLIP-v1"
DEVICE_LABEL = b"DEVICE-CONFIRM-v1"

GET_PUBKEY = 0x01
PUBKEY = 0x81
SIGN_REQUEST = 0x02
SIGN_RESULT = 0x82
MAX_PAYLOAD = 512

STATUS_OK = 0
STATUS_REJECTED = 1      # người dùng từ chối (hoặc thiết bị không ký được)
STATUS_BAD_BANK_SIG = 2
STATUS_BAD_FORMAT = 3

SIG_LEN = 64
PUB_LEN = 65

MAX_ACCOUNT = 19
MAX_NAME = 64

# Quy tắc ký tự của tên (SPEC §3, R3, R9): ASCII in được + 134 chữ tiếng Việt dựng sẵn.
# Thiết bị chỉ ký thứ nó hiện đúng được lên màn hình; bảng này cũng là danh sách glyph cần có trong font.
# Thay cho kiểm tra NFC (chip không có bảng Unicode). Firmware C phải dùng ĐÚNG bảng này
# (chép nguyên thành một mảng uint16_t). Mã điểm Unicode, xếp tăng dần.
VIET_LETTERS = [
    0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C8, 0x00C9, 0x00CA, 0x00CC,   # À Á Â Ã È É Ê Ì
    0x00CD, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D9, 0x00DA, 0x00DD,   # Í Ò Ó Ô Õ Ù Ú Ý
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E8, 0x00E9, 0x00EA, 0x00EC,   # à á â ã è é ê ì
    0x00ED, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F9, 0x00FA, 0x00FD,   # í ò ó ô õ ù ú ý
    0x0102, 0x0103, 0x0110, 0x0111, 0x0128, 0x0129, 0x0168, 0x0169,   # Ă ă Đ đ Ĩ ĩ Ũ ũ
    0x01A0, 0x01A1, 0x01AF, 0x01B0, 0x1EA0, 0x1EA1, 0x1EA2, 0x1EA3,   # Ơ ơ Ư ư Ạ ạ Ả ả
    0x1EA4, 0x1EA5, 0x1EA6, 0x1EA7, 0x1EA8, 0x1EA9, 0x1EAA, 0x1EAB,   # Ấ ấ Ầ ầ Ẩ ẩ Ẫ ẫ
    0x1EAC, 0x1EAD, 0x1EAE, 0x1EAF, 0x1EB0, 0x1EB1, 0x1EB2, 0x1EB3,   # Ậ ậ Ắ ắ Ằ ằ Ẳ ẳ
    0x1EB4, 0x1EB5, 0x1EB6, 0x1EB7, 0x1EB8, 0x1EB9, 0x1EBA, 0x1EBB,   # Ẵ ẵ Ặ ặ Ẹ ẹ Ẻ ẻ
    0x1EBC, 0x1EBD, 0x1EBE, 0x1EBF, 0x1EC0, 0x1EC1, 0x1EC2, 0x1EC3,   # Ẽ ẽ Ế ế Ề ề Ể ể
    0x1EC4, 0x1EC5, 0x1EC6, 0x1EC7, 0x1EC8, 0x1EC9, 0x1ECA, 0x1ECB,   # Ễ ễ Ệ ệ Ỉ ỉ Ị ị
    0x1ECC, 0x1ECD, 0x1ECE, 0x1ECF, 0x1ED0, 0x1ED1, 0x1ED2, 0x1ED3,   # Ọ ọ Ỏ ỏ Ố ố Ồ ồ
    0x1ED4, 0x1ED5, 0x1ED6, 0x1ED7, 0x1ED8, 0x1ED9, 0x1EDA, 0x1EDB,   # Ổ ổ Ỗ ỗ Ộ ộ Ớ ớ
    0x1EDC, 0x1EDD, 0x1EDE, 0x1EDF, 0x1EE0, 0x1EE1, 0x1EE2, 0x1EE3,   # Ờ ờ Ở ở Ỡ ỡ Ợ ợ
    0x1EE4, 0x1EE5, 0x1EE6, 0x1EE7, 0x1EE8, 0x1EE9, 0x1EEA, 0x1EEB,   # Ụ ụ Ủ ủ Ứ ứ Ừ ừ
    0x1EEC, 0x1EED, 0x1EEE, 0x1EEF, 0x1EF0, 0x1EF1, 0x1EF2, 0x1EF3,   # Ử ử Ữ ữ Ự ự Ỳ ỳ
    0x1EF4, 0x1EF5, 0x1EF6, 0x1EF7, 0x1EF8, 0x1EF9,                   # Ỵ ỵ Ỷ ỷ Ỹ ỹ
]
assert len(VIET_LETTERS) == 134


def name_char_allowed(ch):
    return 0x20 <= ord(ch) <= 0x7E or ord(ch) in VIET_LETTERS


def sha256(data):
    return hashlib.sha256(data).digest()


# ---------- Phiếu giao dịch (SPEC §3) ----------
# slip = nonce(16) ‖ amount(8) ‖ len ‖ to_account ‖ len ‖ to_name

def encode_slip(nonce, amount, to_account, to_name):
    """Ngân hàng dùng. Chuẩn hóa tên về NFC để chữ có dấu thành dạng dựng sẵn,
    đúng với bảng ký tự cho phép (SPEC §3)."""
    account = to_account.encode("ascii")
    name = unicodedata.normalize("NFC", to_name).encode("utf-8")
    slip = (nonce + amount.to_bytes(8, "big")
            + bytes([len(account)]) + account
            + bytes([len(name)]) + name)
    # Giải mã lại để chắc chắn ngân hàng không phát ra phiếu mà thiết bị sẽ từ chối.
    if len(nonce) != 16 or decode_slip(slip) is None:
        raise ValueError("phiếu không hợp lệ")
    return slip


def decode_slip(slip):
    """Thiết bị dùng. Trả về dict 4 trường, hoặc None nếu sai định dạng (R1, R9).

    Từ chối: thiếu byte, thừa byte, số TK không phải 1–19 chữ số,
    số tiền bằng 0, tên rỗng hoặc dài quá 64 byte, tên không phải UTF-8 hợp lệ,
    tên có ký tự ngoài bảng cho phép (dấu kết hợp, xuống dòng, ...).
    """
    if len(slip) < 16 + 8 + 1:
        return None
    nonce = slip[0:16]
    amount = int.from_bytes(slip[16:24], "big")

    account_len = slip[24]
    account = slip[25:25 + account_len]
    pos = 25 + account_len
    if pos >= len(slip):                       # thiếu byte độ dài của tên
        return None
    name_len = slip[pos]
    name = slip[pos + 1:pos + 1 + name_len]
    if pos + 1 + name_len != len(slip):        # thừa hoặc thiếu byte
        return None

    if amount < 1:                             # SPEC §3: số tiền >= 1
        return None
    if account_len < 1 or account_len > MAX_ACCOUNT:
        return None
    for c in account:
        if c < 0x30 or c > 0x39:               # chỉ chữ số '0'..'9'
            return None
    if name_len < 1 or name_len > MAX_NAME:
        return None
    try:
        name_text = name.decode("utf-8")
    except UnicodeDecodeError:
        return None
    for ch in name_text:                       # R3, R9: chỉ ký tự hiện đúng được lên màn hình
        if not name_char_allowed(ch):
            return None

    return {"nonce": nonce, "amount": amount,
            "to_account": account.decode("ascii"), "to_name": name_text}


# ---------- Hai thông điệp được ký (SPEC §4) ----------
# Hai nhãn khác nhau: chữ ký bên này không dùng thay chữ ký bên kia được (R1).

def bank_message(slip):
    return BANK_LABEL + slip


def device_message(slip, counter):
    # Ký trên SHA256(slip): đổi 1 byte phiếu là chữ ký sai (R4). Có counter để phát hiện nhân bản (R6).
    return DEVICE_LABEL + sha256(slip) + counter.to_bytes(4, "big")


# ---------- ECDSA P-256 + SHA-256 (SPEC §2) ----------
# Khóa bí mật: 32 byte. Khóa công khai: 65 byte không nén. Chữ ký: r‖s 64 byte.

def new_private_key():
    return SigningKey.generate(curve=NIST256p).to_string()


def public_key(priv):
    return SigningKey.from_string(priv, curve=NIST256p).get_verifying_key().to_string("uncompressed")


def key_id(pub):
    """Mã nhận dạng khóa: 8 byte đầu của SHA256(DK_pub), để người dùng so khớp khi đăng ký (R7)."""
    return sha256(pub)[:8]


def sign(priv, message):
    # k sinh theo RFC 6979 (R4): cùng khóa + cùng thông điệp → cùng chữ ký, so được với test vectors.
    # Tương đương mbedtls_ecdsa_sign_det_ext(..., MBEDTLS_MD_SHA256, ...) trên hash SHA256(message).
    sk = SigningKey.from_string(priv, curve=NIST256p)
    return sk.sign_digest_deterministic(sha256(message), hashfunc=hashlib.sha256,
                                        sigencode=sigencode_string)


def verify(pub, message, sig):
    if len(pub) != PUB_LEN or len(sig) != SIG_LEN:
        return False
    vk = VerifyingKey.from_string(pub, curve=NIST256p)
    try:
        return vk.verify_digest(sig, sha256(message), sigdecode=sigdecode_string)
    except BadSignatureError:
        return False


# ---------- Khung USB (SPEC §7) ----------
# TYPE(1) ‖ LEN(2, big-endian) ‖ PAYLOAD, LEN ≤ 512.

def make_frame(ftype, payload):
    return bytes([ftype]) + len(payload).to_bytes(2, "big") + payload


def parse_frame(frame):
    """Trả về (type, payload), hoặc None nếu sai độ dài (R9). Không kiểm tra TYPE ở đây."""
    if len(frame) < 3:
        return None
    length = int.from_bytes(frame[1:3], "big")
    if length > MAX_PAYLOAD or len(frame) != 3 + length:
        return None
    return frame[0], frame[3:]


def result_frame(status, counter=0, sig=b""):
    """SIGN_RESULT. Status khác 0 thì payload chỉ có 1 byte status (không có counter, chữ ký)."""
    if status != STATUS_OK:
        return make_frame(SIGN_RESULT, bytes([status]))
    return make_frame(SIGN_RESULT, bytes([status]) + counter.to_bytes(4, "big") + sig)
