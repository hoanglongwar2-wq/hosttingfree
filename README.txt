# Python Host — web chạy file Python (3.9 – 3.13)

Tải file `.py` (hoặc cả dự án `.zip`) lên, bấm ▶ Chạy là chương trình chạy nền trên máy chủ. Xem log trực tiếp, sửa file ngay trên web, đặt biến môi trường (token bot), cài thư viện từ `requirements.txt`, tự chạy lại khi sập.

## Tính năng
- Đăng nhập email/mật khẩu, Google, Facebook. Tài khoản mới **chờ admin duyệt**.
- Mỗi người nhiều dự án; chạy / dừng / chạy lại; log thời gian thực; tự khởi động lại khi lỗi (tối đa 8 lần/10 phút).
- Máy chủ khởi động lại thì tự chạy lại các dự án đang ở trạng thái "chạy".
- Giới hạn RAM mỗi chương trình, số chương trình chạy cùng lúc, dung lượng mỗi người.
- Admin: duyệt/khóa/xóa người dùng, đổi mật khẩu, xem và dừng mọi chương trình đang chạy.

## Đưa lên Render
1. Tạo repository **Private** trên GitHub, upload toàn bộ file ở thư mục gốc.
2. Render → New → Blueprint → chọn repository. (Hoặc Web Service, Start Command: `gunicorn backend:app --workers 1 --threads 8 --timeout 120`.)
3. Điền `ADMIN_EMAIL`, `ADMIN_PASSWORD` trong Environment (hoặc trong `config.py`).

## Hạn chế cần biết (đặc biệt gói Free của Render)
- **Tự ngủ:** gói Free ngủ sau ~15 phút không có người truy cập web, chương trình đang chạy sẽ dừng. Dùng UptimeRobot (miễn phí) ping `https://TEN-BAN.onrender.com/api/health` mỗi 5 phút để giữ máy thức.
- **Mất dữ liệu:** đĩa của gói Free là tạm, mỗi lần deploy/khởi động lại sẽ mất tài khoản và file. Muốn lâu dài: gắn Disk (gói trả phí) tại `/var/data` và đặt `DB_PATH=/var/data/pyhost.db`.
- **Tài nguyên:** gói Free chỉ có 512 MB RAM và CPU yếu, hợp bot nhỏ (Telegram/Discord, script định kỳ), không hợp việc nặng.

## An toàn
Chương trình người dùng chạy **trên cùng máy chủ**, không phải container cô lập. Mỗi chương trình có môi trường sạch (không thấy mật khẩu/khóa của máy chủ qua biến môi trường), bị giới hạn RAM, nhưng một người có ý xấu vẫn có thể đọc file trên máy chủ. Vì vậy:
- Giữ `AUTO_APPROVE=0` và chỉ duyệt người bạn tin.
- Repository GitHub phải để Private nếu `config.py` có mật khẩu.
- Cần cô lập thật sự (nhiều người lạ dùng) thì phải chạy bằng Docker/VPS riêng, không nên dùng Render Free.

## Chọn phiên bản Python (3.9 / 3.10 / 3.11 / 3.12 / 3.13)
Vào dự án → Cài đặt → "Phiên bản Python". Máy chủ dùng sẵn `python3.x` nếu có, nếu chưa có thì tự tải bằng `uv` (cần mạng, lần đầu 10–60 giây, lưu vào thư mục `pythons/` cạnh database). Mỗi dự án chọn riêng. Đổi phiên bản xong hãy cài lại `requirements.txt`.

## Tự cài thư viện
Khi bấm ▶ Chạy mà dự án có `requirements.txt` mới hoặc vừa đổi, máy chủ tự chạy `pip install` trước rồi mới chạy chương trình (xem tiến trình ở tab Log). Cài lỗi thì không chạy và báo trong log. Giờ trong log theo múi giờ `TZ` (mặc định Asia/Ho_Chi_Minh).

## API nâng cao
- **API token:** menu avatar → "API token". Gọi API không cần đăng nhập: `curl -H "Authorization: Bearer ph_xxx" https://<host>/api/projects`. Token chỉ hiện một lần, thu hồi bất cứ lúc nào. Token không tạo/xóa được token khác.
- **Log trực tiếp:** `GET /api/projects/<id>/logs/stream` (Server-Sent Events: init, log, status, reset). Tối đa 4 luồng cùng lúc.
- **Thống kê:** `GET /api/projects/<id>/stats` → CPU %, RAM, số luồng, uptime, dung lượng, số lần tự chạy lại.
- **Xuất dự án:** `GET /api/projects/<id>/export` → file .zip. Đổi tên file: `POST /api/projects/<id>/rename` `{"path","new"}`.
