# CLAUDE.md — Thiết bị ký xác nhận giao dịch

## Bối cảnh

Bài tập lớn môn An toàn hệ thống thông tin (Thạc sĩ, HUST), giảng viên TS. Nguyễn Khanh Văn.
Đề tài: **Xác thực ý định giao dịch trong ngân hàng số: mô hình đe dọa và thiết bị ký xác nhận giao dịch.**

- Cao Đức Anh (kỹ sư nhúng): firmware thiết bị.
- Võ Việt Hoàng (kỹ sư phần mềm): server ngân hàng và trang web.

**Thầy chấm qua vấn đáp kỹ. Hiểu quan trọng hơn code.** Người dùng phải giải thích được từng dòng mình nộp. Vì vậy:
- Code ngắn, đơn giản, dễ đọc. Không tối ưu sớm, không trừu tượng hóa thừa, ít thư viện.
- Mỗi cơ chế an toàn có comment trỏ về mục trong `SPEC.md` và mã yêu cầu R1–R9.
- Sau mỗi bước, giải thích ngắn bằng tiếng Việt: đã làm gì, vì sao, liên quan yêu cầu nào.
- Comment và giải thích viết bằng tiếng Việt. Tên biến, hàm bằng tiếng Anh.

## Nguồn sự thật

**`SPEC.md` là hợp đồng giữa thiết bị và server.** Không tự ý làm khác đặc tả. Thấy đặc tả thiếu hoặc sai thì dừng lại, đề xuất sửa `SPEC.md` trước, được đồng ý rồi mới code.

Chuỗi liên kết giữa các tuần, mọi thứ phải lần ngược được:
Mối đe dọa (T1–T4) → Yêu cầu (R1–R9, báo cáo tuần 1) → Cơ chế (tuần 2, `SPEC.md`) → Phép thử tấn công (tuần 3).

## Cấu trúc thư mục

```
SPEC.md              đặc tả giao thức (v0.3)
proto/               mô phỏng Python cả hai phía — bản tham chiếu
  common.py          mã hóa phiếu, ký/kiểm tra, khung USB
  bank.py            phía ngân hàng
  device.py          thiết bị giả lập (logic sẽ chuyển sang C)
  demo.py            chạy quy trình + các tình huống tấn công
  gen_vectors.py     sinh test_vectors.json
firmware/            ESP-IDF, ESP32-S3
server/  web/        phần của Hoàng (chưa chốt công nghệ)
```

## Thứ tự công việc

1. ~~Đặc tả giao thức~~ (xong, `SPEC.md` v0.3)
2. ~~Mô phỏng Python~~ trong `proto/` + sinh `test_vectors.json` (xong; đang cập nhật theo SPEC v0.3).
3. Gửi `SPEC.md` + `test_vectors.json` cho Hoàng.
4. Khi mạch về: dựng phần cứng (màn hình hiện chữ, đọc nút, thông USB). Không phụ thuộc giao thức.
5. Chuyển logic `device.py` sang C. Kết quả phải khớp **từng byte** với `test_vectors.json`. Sau đó ghép với server.
6. Bật flash encryption + NVS encryption ở development mode; demo đọc flash trước và sau.

## Điều kiện hoàn thành bước 2

`python3 proto/demo.py` chạy đúng kỳ vọng tất cả tình huống:

| # | Tình huống | Kỳ vọng | Yêu cầu |
|---|---|---|---|
| 1 | Đăng ký, so mã nhận dạng khóa | khớp | R7 |
| 2 | Giao dịch bình thường | chuyển tiền | — |
| 3 | Mã độc sửa số tiền trước khi xuống thiết bị | thiết bị trả 2 | R2 |
| 4 | Mã độc tạo giao dịch thật tới kẻ gian, tráo phiếu | người dùng thấy lạ, từ chối | R3 |
| 5 | Mã độc sửa counter trong kết quả | ngân hàng: sai chữ ký | R4 |
| 6 | Phát lại kết quả cũ | ngân hàng: nonce đã dùng | R5 |
| 7 | Dùng chữ ký cũ cho giao dịch mới | ngân hàng từ chối | R4, R6 |
| 8 | Gửi kết quả sau 200 giây | ngân hàng: hết hạn | R5 |
| 9 | Bản sao thiết bị (chép flash) ký | ngân hàng: counter không tăng | R6 |
| 10 | Khung USB rác, sai độ dài | thiết bị trả 3, không lỗi | R9 |
| 11 | Sai PIN 5 lần | khóa bị xóa | R8 |

`python3 proto/gen_vectors.py` chạy hai lần phải ra file giống hệt nhau.

## Phần cứng

- Board ESP32-S3 DevKitC-1, bản N16R8 (16MB flash, 8MB PSRAM), 2 cổng USB-C:
  - cổng **USB** (nối thẳng vào chip): giao tiếp với trình duyệt qua WebSerial;
  - cổng **COM/UART**: nạp firmware và xem log.
- Màn TFT 1,54" ST7789, 240×240, SPI, 8 chân. Chân ghi SCL/SDA thực chất là SCK/MOSI của SPI, không phải I2C.
- 2 nút nhấn 2 chân: một chân vào GPIO, một chân vào GND, bật pull-up nội.
- Kiểm tra board khi nhận: `esptool.py flash_id` phải ra flash 16MB và có PSRAM 8MB.

## Quy tắc kỹ thuật bắt buộc

- Chữ ký dạng **r‖s 64 byte**, không dùng DER. Khóa công khai không nén 65 byte.
- Ký **xác định theo RFC 6979**: Python dùng `ecdsa` với `sign_digest_deterministic`; mbedTLS dùng `mbedtls_ecdsa_sign_det_ext`. Không dùng thư viện `cryptography` để ký vì k ngẫu nhiên, không so được với test vectors.
- Số nguyên big-endian. Tên người nhận theo **quy tắc ký tự ở SPEC §3** (ASCII in được + 134 chữ tiếng Việt dựng sẵn), không dùng kiểm tra NFC; Python và C phải dùng cùng một bảng ký tự.
- Thiết bị **kiểm tra chữ ký ngân hàng trước, giải mã phiếu sau**.
- Thiết bị tăng counter và **ghi flash trước khi ký**. Tăng số lần sai PIN và ghi flash **trước khi so PIN**.
- Ngân hàng **đánh dấu nonce đã dùng ngay**, trước các bước kiểm tra khác.
- **Hạn dùng do ngân hàng kiểm tra**, thiết bị không có đồng hồ tin cậy.
- Flash encryption **không** bảo vệ phân vùng NVS. Khóa lưu trong NVS thì phải bật thêm NVS encryption.
- WebSerial chỉ chạy trên Chrome/Edge, trang phải mở qua HTTPS hoặc localhost.

## Tuyệt đối không

- **Không ghi eFuse không đảo ngược được** (release mode của flash encryption, Secure Boot, vô hiệu hóa JTAG/download mode) khi chưa có xác nhận rõ ràng của người dùng. Chỉ có 1 board.
- Không dùng code hay dữ liệu nội bộ của LG hoặc BIDV.
- Không dùng khóa trong `test_vectors.json` cho bất cứ việc gì ngoài kiểm thử.
- Không thêm tính năng ngoài `SPEC.md` (OTA, Wi-Fi, Bluetooth, …). Đề tài cần trọng tâm.
