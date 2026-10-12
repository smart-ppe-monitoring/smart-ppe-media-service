import { z } from "zod";
import {
  IMAGE_FIT,
  IMAGE_FORMAT,
  MEDIA_FOLDER,
  MEDIA_LIMITS,
} from "../../common/constants/media.constant";

const fitEnumValues = Object.values(IMAGE_FIT) as [string, ...string[]];
const formatEnumValues = Object.values(IMAGE_FORMAT) as [string, ...string[]];

export const fileIdParamSchema = z.object({
  id: z.string().uuid("ID tệp phải là định dạng UUID hợp lệ"),
});

export const requestUploadUrlSchema = z.object({
  fileName: z
    .string()
    .trim()
    .min(1, "Tên tệp không được để trống")
    .max(255, "Tên tệp không được vượt quá 255 ký tự"),
  mimeType: z
    .string()
    .trim()
    .min(1, "MIME type không được để trống")
    .max(100, "MIME type không được vượt quá 100 ký tự")
    .regex(
      /^[a-zA-Z0-9!#$&^_.+-]+\/[a-zA-Z0-9!#$&^_.+-]+$/,
      "MIME type không hợp lệ",
    ),
  size: z
    .number()
    .int()
    .nonnegative()
    .max(104857600, "Kích thước tệp tối đa 100MB")
    .optional()
    .default(0),
  folder: z
    .string()
    .trim()
    .regex(
      /^[a-z0-9_-]+$/i,
      "Tên thư mục chỉ chứa chữ cái, số, gạch dưới và gạch ngang",
    )
    .max(50, "Tên thư mục tối đa 50 ký tự")
    .optional()
    .default("general"),
  isPublic: z.boolean().optional().default(false),
  metadata: z
    .record(z.union([z.string().max(500), z.number(), z.boolean()]))
    .refine((obj) => Object.keys(obj).length <= 20, {
      message: "Metadata không được vượt quá 20 trường",
    })
    .optional(),
});

export const confirmUploadSchema = z.object({
  size: z.number().int().nonnegative().max(104857600).optional(),
});

export const listFilesSchema = z.object({
  folder: z.string().optional(),
  isPublic: z
    .enum(["true", "false"])
    .transform((v) => v === "true")
    .optional(),
  mimeType: z.string().optional(),
  search: z
    .string()
    .trim()
    .max(100, "Từ khóa tìm kiếm tối đa 100 ký tự")
    .optional(),
  userId: z.string().uuid("User ID phải là UUID").optional(),
  sortBy: z.enum(["createdAt", "fileName", "size"]).optional(),
  order: z.enum(["asc", "desc"]).optional(),
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().min(1).max(100).optional().default(20),
});

export const imageTransformSchema = z.object({
  width: z.coerce
    .number()
    .int()
    .min(MEDIA_LIMITS.MIN_DIMENSION)
    .max(MEDIA_LIMITS.MAX_DIMENSION)
    .optional(),
  height: z.coerce
    .number()
    .int()
    .min(MEDIA_LIMITS.MIN_DIMENSION)
    .max(MEDIA_LIMITS.MAX_DIMENSION)
    .optional(),
  fit: z.enum(fitEnumValues).optional(),
  format: z.enum(formatEnumValues).optional(),
  quality: z.coerce
    .number()
    .int()
    .min(MEDIA_LIMITS.MIN_QUALITY)
    .max(MEDIA_LIMITS.MAX_QUALITY)
    .optional(),
  saveAsNew: z
    .enum(["true", "false"])
    .transform((v) => v === "true")
    .or(z.boolean())
    .optional(),
});

export const directImageUploadSchema = z.object({
  folder: z
    .string()
    .trim()
    .regex(
      /^[a-z0-9_-]+$/i,
      "Tên thư mục chỉ chứa chữ cái, số, gạch dưới và gạch ngang",
    )
    .max(50)
    .optional()
    .default(MEDIA_FOLDER.IMAGES),
  isPublic: z
    .enum(["true", "false"])
    .transform((v) => v === "true")
    .or(z.boolean())
    .optional()
    .default(true),
  width: z.coerce
    .number()
    .int()
    .min(MEDIA_LIMITS.MIN_DIMENSION)
    .max(MEDIA_LIMITS.MAX_DIMENSION)
    .optional(),
  height: z.coerce
    .number()
    .int()
    .min(MEDIA_LIMITS.MIN_DIMENSION)
    .max(MEDIA_LIMITS.MAX_DIMENSION)
    .optional(),
  fit: z.enum(fitEnumValues).optional(),
  format: z.enum(formatEnumValues).optional(),
  quality: z.coerce
    .number()
    .int()
    .min(MEDIA_LIMITS.MIN_QUALITY)
    .max(MEDIA_LIMITS.MAX_QUALITY)
    .optional(),
});

export const cleanupFilesSchema = z.object({
  unconfirmedMaxAgeHours: z.coerce
    .number()
    .int()
    .positive()
    .max(720)
    .optional()
    .default(24),
  softDeletedRetentionDays: z.coerce
    .number()
    .int()
    .positive()
    .max(365)
    .optional()
    .default(30),
});
