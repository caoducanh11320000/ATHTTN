# Đặc tả giao thức xác nhận giao dịch — v0.3

Nhóm: Cao Đức Anh (thiết bị) · Võ Việt Hoàng (ngân hàng, web)
Mã R1–R9 trỏ về bảng yêu cầu của báo cáo tuần 1.

Thay đổi so với v0.2: quy tắc ký tự của tên thay cho kiểm tra NFC; tên tối đa 64 byte; số tiền ≥ 1; màn hình không hiện nonce; ghi rõ API trình duyệt → server; ngân hàng khóa thiết bị khi chữ ký đúng mà counter không tăng (kiểm tra chữ ký trước counter); thêm mục giới hạn đã biết.

## 1. Ý tưởng trong một câu

Ngân hàng ký phiếu → thiết bị kiểm tra chữ ký, hiện phiếu lên màn hình → người dùng bấm đồng ý → thiết bị ký lại → ngân hàng kiểm tra rồi mới chuyển tiền. Trình duyệt ở giữa chỉ chuyển dữ liệu và **không được tin**.

## 2. Mật mã

- ECDSA P-256 + SHA-256, k sinh theo RFC 6979 (R4).
- Chữ ký dạng `r‖s` 64 byte. Khóa công khai dạng không nén 65 byte.
- Ngân hàng giữ khóa `BK`. Thiết bị giữ khóa `DK`, tự sinh và không bao giờ đưa ra ngoài. `BK_pub` nạp sẵn trong firmware.

## 3. Phiếu giao dịch: 4 trường

| Trường | Kiểu | Giới hạn | Vì sao cần |
|---|---|---|---|
| `nonce` | 16 byte ngẫu nhiên | | Mã giao dịch, đồng thời chống phát lại (R5) |
| `amount` | số nguyên 8 byte | ≥ 1, đơn vị đồng | Thứ kẻ gian muốn sửa |
| `to_account` | chuỗi | 1–19 chữ số `0`–`9` | Thứ kẻ gian muốn sửa |
| `to_name` | chuỗi UTF-8 | 1–64 byte, ký tự theo quy tắc bên dưới | Tên do ngân hàng tra cứu, giúp người dùng nhận ra tài khoản lạ (R3) |

**Mã hóa (R1):** `slip = nonce ‖ amount ‖ len(to_account) ‖ to_account ‖ len(to_name) ‖ to_name`
Số nguyên big-endian; mỗi chuỗi có 1 byte độ dài đứng trước; không thừa, không thiếu byte.

**Quy tắc ký tự của `to_name` (R3, R9):** mỗi ký tự phải thuộc một trong hai nhóm:
- ASCII in được: `0x20`–`0x7E`;
- 134 chữ cái tiếng Việt **dựng sẵn** (chữ thường và hoa): À Á Â Ã È É Ê Ì Í Ò Ó Ô Õ Ù Ú Ý, Ă Đ Ĩ Ũ Ơ Ư, và dải U+1EA0–U+1EF9.

Mọi ký tự khác bị từ chối, kể cả dấu kết hợp (U+0300–U+036F) và ký tự điều khiển như xuống dòng. Lý do: thiết bị chỉ được ký thứ nó hiện đúng được lên màn hình. Quy tắc này thay cho kiểm tra NFC, vì chip không có bảng Unicode. Chữ ký không bị ảnh hưởng: thiết bị băm đúng các byte ngân hàng đã ký, không mã hóa lại.

## 4. Hai chữ ký

```
bank_sig   = Sign(BK, SHA256("BANK-SLIP-v1"      ‖ slip))
device_sig = Sign(DK, SHA256("DEVICE-CONFIRM-v1" ‖ SHA256(slip) ‖ counter))
```

- Chữ ký ngân hàng: thiết bị chỉ ký phiếu thật do ngân hàng phát (R2).
- Chữ ký thiết bị: ngân hàng biết người dùng đã thấy đúng phiếu này. Đổi 1 byte của phiếu là chữ ký sai.
- Hai nhãn khác nhau để chữ ký bên này không dùng thay chữ ký bên kia được (R1).
- `counter` (4 byte): thiết bị tăng 1 và ghi flash trước mỗi lần ký; ngân hàng chỉ nhận giá trị lớn hơn lần trước, nhờ vậy phát hiện thiết bị bị nhân bản (R6).

## 5. Ai kiểm tra cái gì

| Thiết bị | Ngân hàng |
|---|---|
| Định dạng phiếu, quy tắc ký tự (R9) | Phiếu còn hạn (120 giây) |
| Chữ ký ngân hàng, **trước** khi giải mã phiếu (R2) | `nonce` chưa dùng; đánh dấu đã dùng ngay (R5) |
| Hiện số tiền, số tài khoản, tên; người dùng bấm đồng ý (R3) | `counter` tăng (R6) |
| PIN: sai 5 lần thì xóa khóa (R8) | Chữ ký thiết bị đúng với khóa đã đăng ký |

Thiết bị không kiểm tra hạn dùng vì nó không có đồng hồ tin cậy. Màn hình không hiện `nonce`: người dùng không cần và không kiểm tra được giá trị này.

## 6. Đăng ký thiết bị (R7)

Thiết bị tự sinh `DK` lần đầu chạy, hiện mã nhận dạng khóa (8 byte đầu của `SHA256(DK_pub)`, 16 ký tự hex) lên màn hình. Ngân hàng nhận `DK_pub` qua kênh đã xác thực, khách hàng so khớp mã trên hai bên, ngân hàng gắn khóa với tài khoản. Demo giả định bước này diễn ra trong môi trường tin cậy.

## 7. Gói tin

### 7.1 USB: trình duyệt ↔ thiết bị (R9)

Khung: `TYPE (1 byte) ‖ LEN (2 byte) ‖ PAYLOAD`, `LEN` ≤ 512. Thiết bị từ chối mọi khung sai độ dài hoặc sai loại (trả `SIGN_RESULT` với status 3).

| TYPE | Hướng | Payload |
|---|---|---|
| `0x01` GET_PUBKEY | Máy → Thiết bị | rỗng |
| `0x81` PUBKEY | Thiết bị → Máy | `DK_pub` (65) |
| `0x02` SIGN_REQUEST | Máy → Thiết bị | `slip` ‖ `bank_sig` (64) |
| `0x82` SIGN_RESULT | Thiết bị → Máy | status = 0: `status` (1) ‖ `counter` (4) ‖ `device_sig` (64)<br>status ≠ 0: chỉ `status` (1) |

`status`: `0` đồng ý · `1` người dùng từ chối, sai PIN hoặc khóa đã bị xóa · `2` sai chữ ký ngân hàng · `3` sai định dạng.

### 7.2 Trình duyệt → server

Trình duyệt gửi lên server: `nonce` (16) và nguyên payload của `SIGN_RESULT`. An toàn vì chữ ký thiết bị phủ `SHA256(slip)`, mà `slip` chứa `nonce`: gắn kết quả vào sai giao dịch thì chữ ký sai.

## 8. Ngân hàng xử lý kết quả

1. Tìm giao dịch theo `nonce`; không có hoặc đã dùng → từ chối. Đánh dấu đã dùng.
2. Quá 120 giây → từ chối.
3. `status` ≠ 0 → từ chối.
4. Thiết bị đã bị khóa → từ chối.
5. Kiểm tra `device_sig` trên phiếu ngân hàng đã lưu → sai thì từ chối.
6. `counter` không lớn hơn lần trước → từ chối, **khóa thiết bị và cảnh báo khách hàng**. Đúng thì chuyển tiền, lưu `counter`.

Bước 5 phải đứng **trước** bước 6. Chữ ký đúng mà counter không tăng nghĩa là có một bản sao khác đang giữ khóa, nên khóa thiết bị. Nếu khóa dựa trên dữ liệu chưa xác thực chữ ký, kẻ gian chỉ cần gửi một counter cũ là khóa được thiết bị của nạn nhân.

## 9. Giới hạn đã biết

- **Nhân bản chỉ bị phát hiện, không bị chặn:** nếu bản sao ký trước, giao dịch của bản sao vẫn qua; ngân hàng chỉ phát hiện ở lần ký sau của thiết bị thật. Cơ chế signCount của FIDO cũng vậy. Lớp chặn thật sự là mã hóa flash và NVS (R8), khiến việc sao chép khóa khó ngay từ đầu.
- **Người dùng không đọc màn hình mà vẫn bấm đồng ý:** giao thức không chống được.
- **Bước đăng ký** dựa trên giả định kênh đã xác thực.
