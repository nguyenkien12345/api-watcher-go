# API Watcher

## Chương trình này làm gì?

Đây là một **proxy** chen vào giữa trình duyệt và server. Hình dung trong Chrome DevTools có tab Network, và bạn có một con bot ngồi canh tab đó:

```
Trình duyệt  ──►  Proxy (chương trình này)  ──►  Server API
              ◄──                            ◄──
```

1. Mỗi request đi qua, proxy kiểm tra URL có khớp **rule** bạn khai báo không (ví dụ URL chứa /api/users).
2. Nếu khớp, **lần đầu tiên** nó lưu response JSON ra file, gọi là **bản gốc (origin)**.
3. **Những lần sau**, nó so response mới với bản gốc. Nếu khác nhau, nó ghi ra `file *_diff.json` và hiện thông báo (toast) trên desktop.

> 🎯 **Mục đích:** là phát hiện khi nào API âm thầm thay đổi dữ liệu.