import { Request, Response, NextFunction } from "express";
import { Prisma } from "@prisma/client-media";
import { ZodError } from "zod";
import multer from "multer";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";

export function notFoundMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  // LOW-01 Fix: Dùng req.path thay cho req.originalUrl để không để lộ query params nhạy cảm
  next(
    new AppError(
      `Route ${req.method} ${req.path} not found`,
      404,
      ERROR_CODE.NOT_FOUND,
    ),
  );
}

/**
 * Khử bỏ các chuỗi dữ liệu nhạy cảm (mật khẩu CSDL, AWS S3 secret keys, Bearer tokens - SEC-49)
 * khỏi các thông báo lỗi và stack trace trước khi ghi ra stdout/stderr container logs.
 */
export function maskSensitiveCredentials(text: string): string {
  if (!text || typeof text !== "string") return text;
  return text
    // 1. Mask chuỗi kết nối CSDL (PostgreSQL, Redis, MongoDB)
    .replace(/(postgres(?:ql)?:\/\/[^:\s@]+:).+?(@[^@\s\/]+(?::\d+)?(?:[/?\s]|$))/gi, "$1***$2")
    .replace(/(redis(?:s)?:\/\/(?:[^:\s@]*:)?).+?(@[^@\s\/]+(?::\d+)?(?:[/?\s]|$))/gi, "$1***$2")
    .replace(/(mongodb(?:\+srv)?:\/\/[^:\s@]+:).+?(@[^@\s\/]+(?::\d+)?(?:[/?\s]|$))/gi, "$1***$2")
    // 2. Mask AWS S3 Presigned parameters
    .replace(/X-Amz-Signature=[a-fA-F0-9]+/gi, "X-Amz-Signature=***")
    .replace(/X-Amz-Credential=[^&\s"']+/gi, "X-Amz-Credential=***")
    .replace(/X-Amz-Security-Token=[^&\s"']+/gi, "X-Amz-Security-Token=***")
    // 3. Mask Authorization Bearer tokens
    .replace(/Bearer\s+[A-Za-z0-9\-_.~+/]+=*/gi, "Bearer ***")
    // 4. Mask các trường JSON hoặc chuỗi cấu hình chứa bí mật
    .replace(
      /((?:password|secret|secretAccessKey|accessKeyId|sessionToken|apiKey|api_key|token|privateKey)\s*[:=]\s*["']?)[^\s"',;]{4,}(["']?)/gi,
      "$1***$2",
    );
}

/**
 * Chuẩn hóa và làm sạch đối tượng Error phục vụ ghi log an toàn (SEC-49)
 */
export function sanitizeErrorForLogging(error: any): {
  name: string;
  message: string;
  code?: string | number;
  stack?: string;
} {
  if (!error) {
    return { name: "UnknownError", message: "Unknown error occurred" };
  }
  const name = error.name || "Error";
  const rawMessage =
    typeof error.message === "string" ? error.message : String(error);
  const sanitizedMessage = maskSensitiveCredentials(rawMessage);
  const sanitizedStack = error.stack
    ? maskSensitiveCredentials(error.stack)
    : undefined;

  return {
    name,
    message: sanitizedMessage,
    code: error.code,
    ...(sanitizedStack ? { stack: sanitizedStack } : {}),
  };
}

export function errorMiddleware(
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  // Bắt ZodError tập trung (RFC 7807 / 422)
  if (error instanceof ZodError) {
    const formattedErrors = error.errors.map((e) => ({
      field: e.path.join(".") || "unknown",
      message: e.message,
    }));
    res.status(422).json({
      success: false,
      message: "Validation failed",
      code: ERROR_CODE.VALIDATION_ERROR,
      errors: formattedErrors,
    });
    return;
  }

  if (error instanceof AppError) {
    const payload: Record<string, any> = {
      success: false,
      message: error.message,
      code: error.code,
    };
    if (error.data !== undefined) {
      if (error.code === ERROR_CODE.VALIDATION_ERROR) {
        payload.errors = error.data;
      } else {
        payload.data = error.data;
      }
    }
    res.status(error.statusCode).json(payload);
    return;
  }

  if (
    error instanceof SyntaxError &&
    "status" in error &&
    (error as any).status === 400
  ) {
    res.status(400).json({
      success: false,
      message: "Invalid JSON payload format",
      code: ERROR_CODE.VALIDATION_ERROR,
    });
    return;
  }

  if (error instanceof multer.MulterError) {
    const message =
      error.code === "LIMIT_FILE_SIZE"
        ? "Kích thước tệp tin vượt quá giới hạn tối đa cho phép"
        : `Lỗi tải lên tệp tin: ${error.message}`;
    res.status(400).json({
      success: false,
      message,
      code: ERROR_CODE.VALIDATION_ERROR,
    });
    return;
  }

  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === "P2002") {
      const conflictingFields =
        (error.meta?.target as string[] | undefined) ?? [];
      if (conflictingFields.some((f) => f.toLowerCase().includes("slug"))) {
        res.status(409).json({
          success: false,
          message: "Đường dẫn định danh đã tồn tại. Vui lòng chọn tên khác.",
          code: ERROR_CODE.DUPLICATE_ENTRY,
        });
        return;
      }
      res.status(409).json({
        success: false,
        message:
          "Dữ liệu đã tồn tại trong hệ thống (trùng lặp giá trị duy nhất)",
        code: ERROR_CODE.DUPLICATE_ENTRY,
      });
      return;
    }

    if (error.code === "P2025") {
      res.status(404).json({
        success: false,
        message: "Bản ghi không tồn tại hoặc đã bị xóa",
        code: ERROR_CODE.NOT_FOUND,
      });
      return;
    }

    if (error.code === "P2003" || error.code === "P2014") {
      res.status(400).json({
        success: false,
        message: "Dữ liệu liên kết hoặc ràng buộc quan hệ không hợp lệ",
        code: ERROR_CODE.VALIDATION_ERROR,
      });
      return;
    }
  }

  if (error instanceof Prisma.PrismaClientValidationError) {
    res.status(400).json({
      success: false,
      message: "Dữ liệu truy vấn không hợp lệ",
      code: ERROR_CODE.VALIDATION_ERROR,
    });
    return;
  }

  // LOW-02 Fix: Sanitize request ID chống tấn công log injection / CRLF
  const rawRequestId = req.headers["x-request-id"] as string;
  const requestId =
    rawRequestId && /^[a-zA-Z0-9_-]{1,64}$/.test(rawRequestId)
      ? rawRequestId
      : req.id || "no-request-id";

  // SEC-49: Làm sạch thông tin nhạy cảm (mật khẩu CSDL, khóa bí mật AWS) trước khi in ra console
  const sanitizedError = sanitizeErrorForLogging(error);
  console.error(`[Unhandled Error][Request-ID: ${requestId}]`, sanitizedError);

  res.status(500).json({
    success: false,
    message: "Internal server error",
    code: ERROR_CODE.INTERNAL_SERVER_ERROR,
  });
}

export const errorHandler = errorMiddleware;
