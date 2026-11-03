# ============================================================
#  CẤU HÌNH PYTHON HOST — chỉ điền những gì bạn cần.
#  Biến môi trường trên Render (Environment) luôn được ưu tiên hơn file này.
#
#  ⚠ File này chứa bí mật (mật khẩu admin). Nếu đưa lên GitHub thì repository PHẢI để PRIVATE.
# ============================================================

# --- 1) TÀI KHOẢN ADMIN (là bạn) ---------------------------------
# Đăng nhập bằng email + mật khẩu này sẽ có nút 👑 Admin để duyệt/khóa người dùng. Mật khẩu từ 8 ký tự.
# Để trống: hệ thống tự tạo admin@huy.local và in mật khẩu trong Render > Logs.
ADMIN_EMAIL = "huymeomeoooo@gmail.com"
ADMIN_PASSWORD = "anhhuy11@@123"

# --- 2) ĐĂNG KÝ ---------------------------------------------------
# AUTO_APPROVE = "0": người mới đăng ký phải chờ admin bấm "Duyệt" (AN TOÀN, khuyên dùng).
# AUTO_APPROVE = "1": ai đăng ký cũng dùng được ngay (không nên: họ chạy code trên máy chủ của bạn).
AUTO_APPROVE = "0"
# ALLOW_REGISTER = "0" để tắt hẳn đăng ký, chỉ mình bạn dùng.
ALLOW_REGISTER = "1"

# --- 3) GIỚI HẠN (áp dụng cho người dùng thường, admin không bị giới hạn số dự án) ---
MAX_PROJECTS = "5"             # số dự án mỗi người
MAX_RUNNING_PER_USER = "2"     # số chương trình chạy cùng lúc mỗi người
MAX_RUNNING_TOTAL = "8"        # tổng số chương trình chạy cùng lúc trên cả máy chủ
USER_QUOTA_MB = "200"          # dung lượng tệp mỗi người
RUN_MEM_MB = "400"             # RAM tối đa mỗi chương trình (vượt quá sẽ bị dừng)

# --- 4) ĐĂNG NHẬP BẰNG GOOGLE / FACEBOOK (tùy chọn, để trống thì ẩn nút) ---
# Google: https://console.cloud.google.com/apis/credentials -> OAuth client ID (Web). Thêm địa chỉ web vào Authorized JavaScript origins.
GOOGLE_CLIENT_ID = ""
# Facebook: https://developers.facebook.com/apps -> thêm "Facebook Login for Web".
FACEBOOK_APP_ID = ""
FACEBOOK_APP_SECRET = ""
