import {
  openapiRegistry,
  PaginationMetaSchema,
} from "../../config/openapi/openapi.registry";
import {
  requestUploadUrlSchema,
  confirmUploadSchema,
  fileIdParamSchema,
  listFilesSchema,
} from "./file.validation";
import { z } from "zod";

export function registerFileOpenApi(): void {
  // Register Schemas
  openapiRegistry.register("RequestUploadUrlRequest", requestUploadUrlSchema);
  openapiRegistry.register("ConfirmUploadRequest", confirmUploadSchema);

  const FileItemSchema = z.object({
    id: z
      .string()
      .uuid()
      .openapi({ example: "01923456-789a-7bc0-8123-456789abcdef" }),
    userId: z
      .string()
      .uuid()
      .nullable()
      .openapi({ example: "01923456-789a-7bc0-8123-456789abcdef" }),
    originalName: z.string().openapi({ example: "invoice-2026.pdf" }),
    fileName: z.string().openapi({ example: "invoice-2026_01923456.pdf" }),
    mimeType: z.string().openapi({ example: "application/pdf" }),
    size: z.number().int().openapi({ example: 1048576 }),
    bucketKey: z
      .string()
      .openapi({ example: "documents/user-id/uuid_invoice-2026.pdf" }),
    folder: z.string().openapi({ example: "documents" }),
    isPublic: z.boolean().openapi({ example: false }),
    isConfirmed: z.boolean().openapi({ example: true }),
    url: z
      .string()
      .optional()
      .openapi({ example: "https://cdn.example.com/documents/..." }),
    metadata: z.record(z.unknown()).optional().nullable(),
    createdAt: z.string().datetime(),
    updatedAt: z.string().datetime(),
    user: z
      .object({
        id: z.string().uuid(),
        fullName: z.string().nullable(),
      })
      .optional()
      .nullable(),
  });

  openapiRegistry.register("FileItem", FileItemSchema);

  // 1. POST /files/upload-url
  openapiRegistry.registerPath({
    method: "post",
    path: "/files/upload-url",
    tags: ["Files & Media Storage"],
    summary:
      "Xin Presigned Upload URL để tải tệp trực tiếp lên S3/R2 (Yêu cầu đăng nhập)",
    security: [{ BearerAuth: [] }],
    request: {
      body: {
        content: {
          "application/json": {
            schema: requestUploadUrlSchema,
          },
        },
      },
    },
    responses: {
      201: {
        description: "Tạo presigned upload URL thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z
                .string()
                .openapi({ example: "Tạo link tải lên thành công" }),
              data: z.object({
                fileId: z.string().uuid(),
                uploadUrl: z.string().url(),
                bucketKey: z.string(),
                isPublic: z.boolean(),
                expiresIn: z.number(),
              }),
            }),
          },
        },
      },
      400: {
        description:
          "Dữ liệu không hợp lệ hoặc định dạng/dung lượng tệp bị từ chối",
      },
      401: { description: "Chưa xác thực" },
    },
  });

  // 2. POST /files/{id}/confirm
  openapiRegistry.registerPath({
    method: "post",
    path: "/files/{id}/confirm",
    tags: ["Files & Media Storage"],
    summary: "Xác nhận đã tải tệp lên S3/R2 thành công",
    security: [{ BearerAuth: [] }],
    request: {
      params: fileIdParamSchema,
      body: {
        content: {
          "application/json": {
            schema: confirmUploadSchema,
          },
        },
      },
    },
    responses: {
      200: {
        description: "Xác nhận tải tệp thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z.string(),
              data: FileItemSchema,
            }),
          },
        },
      },
      400: { description: "Tệp đã được xác nhận trước đó" },
      403: { description: "Không có quyền xác nhận tệp của người khác" },
      404: { description: "Không tìm thấy tệp" },
    },
  });

  // 3. GET /files
  openapiRegistry.registerPath({
    method: "get",
    path: "/files",
    tags: ["Files & Media Storage"],
    summary:
      "Danh sách tệp tin (hỗ trợ lọc theo thư mục, public/private, tìm kiếm)",
    security: [{ BearerAuth: [] }],
    request: {
      query: listFilesSchema,
    },
    responses: {
      200: {
        description: "Lấy danh sách tệp thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.array(FileItemSchema),
              meta: PaginationMetaSchema,
            }),
          },
        },
      },
    },
  });

  // 4. GET /files/{id}
  openapiRegistry.registerPath({
    method: "get",
    path: "/files/{id}",
    tags: ["Files & Media Storage"],
    summary: "Chi tiết thông tin tệp tin",
    security: [{ BearerAuth: [] }],
    request: {
      params: fileIdParamSchema,
    },
    responses: {
      200: {
        description: "Lấy thông tin tệp thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: FileItemSchema,
            }),
          },
        },
      },
      403: { description: "Không có quyền xem tệp riêng tư này" },
      404: { description: "Không tìm thấy tệp" },
    },
  });

  // 5. GET /files/{id}/download-url
  openapiRegistry.registerPath({
    method: "get",
    path: "/files/{id}/download-url",
    tags: ["Files & Media Storage"],
    summary:
      "Lấy Presigned Download URL có chữ ký và thời hạn để tải tệp riêng tư",
    security: [{ BearerAuth: [] }],
    request: {
      params: fileIdParamSchema,
    },
    responses: {
      200: {
        description: "Lấy download URL thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              data: z.object({
                downloadUrl: z.string().url(),
                expiresIn: z.number(),
                fileName: z.string(),
              }),
            }),
          },
        },
      },
      400: { description: "Tệp chưa hoàn tất tải lên hoặc chưa được xác nhận" },
      403: { description: "Không có quyền truy cập tệp" },
      404: { description: "Không tìm thấy tệp" },
    },
  });

  // 6. GET /files/{id}/download
  openapiRegistry.registerPath({
    method: "get",
    path: "/files/{id}/download",
    tags: ["Files & Media Storage"],
    summary: "Chuyển hướng (302 Redirect) trực tiếp đến download URL của tệp",
    security: [{ BearerAuth: [] }],
    request: {
      params: fileIdParamSchema,
    },
    responses: {
      302: { description: "Chuyển hướng trực tiếp tới URL tệp tin" },
      400: { description: "Tệp chưa hoàn tất tải lên hoặc chưa được xác nhận" },
      403: { description: "Không có quyền truy cập tệp" },
      404: { description: "Không tìm thấy tệp" },
    },
  });

  // 7. DELETE /files/{id}
  openapiRegistry.registerPath({
    method: "delete",
    path: "/files/{id}",
    tags: ["Files & Media Storage"],
    summary: "Xóa tệp tin khỏi cơ sở dữ liệu và lưu trữ S3/R2",
    security: [{ BearerAuth: [] }],
    request: {
      params: fileIdParamSchema,
    },
    responses: {
      200: {
        description: "Xóa tệp thành công",
        content: {
          "application/json": {
            schema: z.object({
              success: z.boolean().openapi({ example: true }),
              message: z.string(),
            }),
          },
        },
      },
      403: { description: "Không có quyền xóa tệp của người khác" },
      404: { description: "Không tìm thấy tệp" },
    },
  });
}
