# smart-ppe-media-service

> **Media & Evidence Storage Microservice (:8890)** cho Hệ thống Giám sát An toàn Lao động Thông minh (**Smart PPE Monitoring System**). Phụ trách lưu trữ hình ảnh/video bằng chứng vi phạm, tích hợp MinIO/S3 Object Storage, cấp Presigned URLs bảo mật và xác thực mã băm toàn vẹn SHA-256 theo chuẩn **D08.pdf (Mục 3.5)**.

---

## 🏛️ Trách nhiệm kiến trúc (Architectural Responsibilities)

1. **Quản lý Bằng chứng Vi phạm (Incident Evidence Storage)**:
   - Lưu trữ ảnh chụp vi phạm kèm bounding box do AI Vision Service gửi sang.
   - Lưu trữ video clip vi phạm (5 - 10 giây) phục vụ công tác thanh tra, hậu kiểm.
   - Tính toán và lưu vết mã băm toàn vẹn **SHA-256 Checksum** chống chối bỏ và chống can thiệp bằng chứng.

2. **Cấp quyền truy cập an toàn (Presigned URL Architecture)**:
   - Cấp **Presigned Upload URL** (TTL ngắn) để Camera Gateway / AI Vision đẩy file trực tiếp lên MinIO/S3 mà không làm nghẽn băng thông backend.
   - Cấp **Presigned Download/View URL** (TTL ngắn) cho frontend Dashboard hiển thị ảnh/video có kiểm soát quyền truy cập.

3. **Tối ưu hóa đa phương tiện (Media Processing Engine)**:
   - Tự động nén, resize và chuyển đổi định dạng ảnh (WebP/AVIF) bằng Sharp để tối ưu dung lượng lưu trữ và tốc độ tải trang.
   - Xử lý thumbnail preview nhanh cho danh sách vi phạm.

4. **Quét dọn tệp rác & Dọn dẹp mồ côi (Orphan Cleanup Worker)**:
   - Quét dọn các tệp upload chưa được xác nhận quá 24h.
   - Xử lý dọn dẹp các bằng chứng đã hết hạn lưu trữ theo chính sách an toàn.

---

## 🔌 Đặc tả kỹ thuật (Technical Specifications)

- **Cổng dịch vụ (Service Port)**: `8890` (Prefix qua API Gateway: `/api/v1/files` và `/api/v1/media`)
- **Object Storage**: MinIO / AWS S3 / Cloudflare R2
- **Thư viện xử lý ảnh**: Sharp, Multer Memory Storage
- **Event Bus**: Kafka / Redis Streams

---

## 🚀 Khởi chạy cục bộ (Local Development)

```bash
# 1. Cài đặt thư viện
pnpm install

# 2. Cấu hình biến môi trường
cp .env.example .env

# 3. Chạy ở chế độ phát triển
pnpm run dev
# Server lắng nghe tại http://localhost:8890
```

---

## 🐳 Triển khai Docker

```bash
docker build -t smart-ppe-media-service .
docker run -p 8890:8890 --env-file .env smart-ppe-media-service
```
