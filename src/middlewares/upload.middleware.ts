import multer from "multer";
import {
  MEDIA_LIMITS,
  SUPPORTED_IMAGE_MIME_TYPES,
} from "../common/constants/media.constant";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";

/**
 * Middleware xử lý upload ảnh vào RAM memory buffer với các giới hạn an toàn:
 * - Kích thước tối đa theo cấu hình MEDIA_LIMITS.MAX_DIRECT_IMAGE_BYTES (10MB) (SEC-11)
 * - Giới hạn số lượng file tối đa: files: 1 nhằm ngăn chặn cạn kiệt bộ nhớ V8 Process RAM (CWE-400)
 * - Lọc MIME type chặt chẽ chỉ chấp nhận ảnh hợp lệ
 */
export const uploadImageMiddleware = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MEDIA_LIMITS.MAX_DIRECT_IMAGE_BYTES,
    files: 1,
    fields: 10,
  },
  fileFilter: (_req, file, cb) => {
    const isSupported = (
      SUPPORTED_IMAGE_MIME_TYPES as readonly string[]
    ).includes(file.mimetype.toLowerCase());
    const isSvgExtension = /\.svgz?$/i.test(file.originalname);
    if (isSupported && !isSvgExtension) {
      cb(null, true);
    } else {
      cb(
        new AppError(
          "Định dạng tệp không được hỗ trợ. Chỉ chấp nhận các định dạng ảnh (JPEG, PNG, WebP, AVIF, GIF, TIFF)",
          400,
          ERROR_CODE.VALIDATION_ERROR,
        ),
      );
    }
  },
});
