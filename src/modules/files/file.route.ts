import { Router } from "express";
import { FileController } from "./file.controller";
import {
  verifyJwtLocally,
  optionalVerifyJwtLocally,
} from "../../middlewares/verify-jwt-locally.middleware";
import {
  requirePermission,
  requireAnyPermission,
} from "../../middlewares/permission.middleware";
import { validate } from "../../middlewares/validate.middleware";
import { uploadImageMiddleware } from "../../middlewares/upload.middleware";
import { PERMISSIONS } from "../../common/constants/permission.constant";
import {
  fileIdParamSchema,
  requestUploadUrlSchema,
  confirmUploadSchema,
  listFilesSchema,
  imageTransformSchema,
  directImageUploadSchema,
  cleanupFilesSchema,
} from "./file.validation";

const router = Router();
const controller = new FileController();

// 1. Xin presigned upload URL (yêu cầu đăng nhập và có quyền FILE_UPLOAD hoặc FILE_MANAGE)
router.post(
  "/upload-url",
  verifyJwtLocally,
  requireAnyPermission(PERMISSIONS.FILE_UPLOAD, PERMISSIONS.FILE_MANAGE),
  validate(requestUploadUrlSchema),
  controller.requestUploadUrl,
);

// 2. Tải lên và tối ưu hóa ảnh trực tiếp bằng Sharp (WebP, avatar, resize)
router.post(
  "/upload-image",
  verifyJwtLocally,
  requireAnyPermission(PERMISSIONS.FILE_UPLOAD, PERMISSIONS.FILE_MANAGE),
  uploadImageMiddleware.single("image"),
  validate(directImageUploadSchema, "body"),
  controller.uploadImage,
);

// 3. Quét dọn tệp tin rác / mồ côi (chỉ Quản trị viên có quyền FILE_MANAGE)
router.post(
  "/cleanup",
  verifyJwtLocally,
  requirePermission(PERMISSIONS.FILE_MANAGE),
  validate(cleanupFilesSchema, "body"),
  controller.cleanupOrphanFiles,
);

// 4. Xác nhận đã upload file lên S3/R2 thành công
router.post(
  "/:id/confirm",
  verifyJwtLocally,
  validate(fileIdParamSchema, "params"),
  validate(confirmUploadSchema),
  controller.confirmUpload,
);

// 5. Danh sách tệp tin (public files hoặc tệp của user)
router.get(
  "/",
  optionalVerifyJwtLocally,
  validate(listFilesSchema, "query"),
  controller.findAll,
);

// 6. Lấy chi tiết thông tin tệp
router.get(
  "/:id",
  optionalVerifyJwtLocally,
  validate(fileIdParamSchema, "params"),
  controller.findById,
);

// 7. Biến đổi ảnh (resize, crop, convert format) qua Sharp
router.get(
  "/:id/transform",
  optionalVerifyJwtLocally,
  validate(fileIdParamSchema, "params"),
  validate(imageTransformSchema, "query"),
  controller.transformImage,
);

// 8. Xin presigned download URL (dành cho file private)
router.get(
  "/:id/download-url",
  optionalVerifyJwtLocally,
  validate(fileIdParamSchema, "params"),
  controller.getDownloadUrl,
);

// 9. Direct download (302 redirect trực tiếp tới signed URL)
router.get(
  "/:id/download",
  optionalVerifyJwtLocally,
  validate(fileIdParamSchema, "params"),
  controller.downloadDirect,
);

// 10. Xóa tệp (yêu cầu đăng nhập và có quyền FILE_DELETE hoặc FILE_MANAGE)
router.delete(
  "/:id",
  verifyJwtLocally,
  requireAnyPermission(PERMISSIONS.FILE_DELETE, PERMISSIONS.FILE_MANAGE),
  validate(fileIdParamSchema, "params"),
  controller.delete,
);

export default router;
