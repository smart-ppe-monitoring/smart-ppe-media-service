import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { jwtConfig } from "../config/jwt.config";
import { jwtKeyService } from "../common/services/jwt-key.service";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";
import { JWT_PURPOSE, JWT_ALGORITHM } from "../common/constants/jwt.constant";

export function extractTokenFromRequest(req: Request): string | undefined {
  let token = req.cookies?.accessToken;
  if (!token) {
    const authHeader = req.headers?.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.split(" ")[1];
    }
  }

  return token;
}

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  // SEC-10: Cấm truyền token xác thực qua query string (?token= hoặc ?ticket=) trên toàn bộ endpoints
  // để triệt tiêu nguy cơ rò rỉ JWT qua access logs, reverse proxy và browser history (RFC 6750 Section 2.3 / CWE-598)
  if (Boolean(req.query && (req.query.token || req.query.ticket))) {
    next(
      new AppError(
        "Không được phép truyền token xác thực qua query parameters để tránh rò rỉ qua access logs và browser history",
        400,
        ERROR_CODE.VALIDATION_ERROR,
      ),
    );
    return;
  }

  const token = extractTokenFromRequest(req);

  if (!token) {
    next(new AppError("Unauthorized", 401, ERROR_CODE.UNAUTHORIZED));
    return;
  }

  try {
    const publicKey = jwtKeyService.getPublicKeyPem() || jwtConfig.publicKey;
    if (!publicKey) {
      next(
        new AppError(
          "Chưa cấu hình khóa công khai JWT",
          500,
          ERROR_CODE.INTERNAL_SERVER_ERROR,
        ),
      );
      return;
    }

    const payload = jwt.verify(token, publicKey, {
      algorithms: [JWT_ALGORITHM.RS256],
    }) as any;

    if (!payload || typeof payload !== "object") {
      next(new AppError("Token không hợp lệ", 401, ERROR_CODE.UNAUTHORIZED));
      return;
    }

    // 5. Kiểm tra mục đích token (bảo vệ chống token tạm thời / 2FA)
    if (
      payload.purpose === JWT_PURPOSE.TWO_FACTOR ||
      payload.type === "TEMP" ||
      (payload.purpose && payload.purpose !== JWT_PURPOSE.ACCESS)
    ) {
      next(
        new AppError(
          "Token không hợp lệ để truy cập tài nguyên được bảo vệ",
          401,
          ERROR_CODE.UNAUTHORIZED,
        ),
      );
      return;
    }

    // SEC-07: Chặn token mang cờ mustChangePassword truy cập tài nguyên
    if (payload.mustChangePassword === true) {
      next(
        new AppError(
          "Yêu cầu đổi mật khẩu trước khi truy cập tài nguyên hệ thống",
          403,
          ERROR_CODE.FORBIDDEN,
        ),
      );
      return;
    }

    req.user = {
      id: payload.id || payload.sub,
      email: payload.email,
      role: payload.role,
      roleId: payload.roleId,
      permissions: Array.isArray(payload.permissions) ? payload.permissions : [],
    };

    next();
  } catch (error) {
    if (error instanceof AppError) {
      next(error);
      return;
    }
    next(new AppError("Token xác thực không hợp lệ hoặc đã hết hạn", 401, ERROR_CODE.UNAUTHORIZED));
  }
}
