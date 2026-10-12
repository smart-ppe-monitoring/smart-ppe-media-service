import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { AppError } from "../common/errors/app-error";
import { ERROR_CODE } from "../common/errors/error-code";
import {
  JWT_ALGORITHM,
  JWKS_CONSTANTS,
  JWT_PURPOSE,
} from "../common/constants/jwt.constant";
import {
  jwtKeyService,
  JwtKeyService,
} from "../common/services/jwt-key.service";
import { jwtConfig } from "../config/jwt.config";
import { extractTokenFromRequest } from "./auth.middleware";

export interface VerifyJwtLocallyOptions {
  /**
   * Khóa công khai RSA PEM trực tiếp (Offline Mode - không phụ thuộc mạng, độ trễ 0.01ms)
   */
  publicKey?: string;
  /**
   * URL của JWKS endpoint (ví dụ: http://auth-service:9999/.well-known/jwks.json)
   */
  jwksUri?: string;
  /**
   * Thời gian sống của cache trong RAM (mặc định 24 giờ)
   */
  cacheTtlMs?: number;
  /**
   * Chế độ xác thực tùy chọn (nếu không có token thì bỏ qua, không trả về 401)
   */
  optional?: boolean;
  /**
   * Tự động làm mới cache khi gặp kid mới (hỗ trợ Key Rotation không downtime)
   */
  autoRefreshOnUnknownKid?: boolean;
}

interface CachedKey {
  pem: string;
  expiresAt: number;
}

/**
 * Bộ nhớ đệm Public Keys trong RAM phục vụ decentralized verification
 * Key: kid (hoặc 'default'), Value: { pem, expiresAt }
 */
const inMemoryKeyCache = new Map<string, CachedKey>();

/**
 * Xóa cache (phục vụ testing hoặc manual invalidation)
 */
export function clearJwtPublicKeyCache(): void {
  inMemoryKeyCache.clear();
}

interface AccessTokenClaims {
  id: string;
  email: string;
  role: string;
  roleId?: string;
  purpose?: string;
  type?: string;
}

/**
 * Lưu key vào RAM cache có giới hạn dung lượng tối đa và dọn dẹp expired (chống DoS / Memory Leak)
 */
function setCachedKey(kid: string, pem: string, expiresAt: number): void {
  const MAX_CACHE_ENTRIES = 100;
  if (inMemoryKeyCache.size >= MAX_CACHE_ENTRIES) {
    const now = Date.now();
    for (const [k, val] of inMemoryKeyCache.entries()) {
      if (val.expiresAt <= now) {
        inMemoryKeyCache.delete(k);
      }
    }
    if (inMemoryKeyCache.size >= MAX_CACHE_ENTRIES) {
      const oldest = inMemoryKeyCache.keys().next().value;
      if (oldest) inMemoryKeyCache.delete(oldest);
    }
  }
  inMemoryKeyCache.set(kid, { pem, expiresAt });
}

/**
 * Nạp Public Key từ JWKS Endpoint từ xa với timeout và caching
 */
async function fetchPublicKeyFromJwks(
  jwksUri: string,
  kid?: string,
  cacheTtlMs: number = JWKS_CONSTANTS.DEFAULT_CACHE_TTL_MS,
): Promise<string> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch(jwksUri, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    });

    if (!response.ok) {
      throw new Error(
        `JWKS HTTP error: ${response.status} ${response.statusText}`,
      );
    }

    const data = (await response.json()) as {
      keys?: Array<Record<string, unknown>>;
    };
    if (!data || !Array.isArray(data.keys) || data.keys.length === 0) {
      throw new Error("JWKS endpoint trả về danh sách keys rỗng");
    }

    const now = Date.now();
    let targetPem = "";

    // Lưu toàn bộ keys nhận được vào RAM cache
    for (const key of data.keys) {
      const currentKid = (key.kid as string) || JWKS_CONSTANTS.DEFAULT_KEY_ID;
      try {
        const pem = JwtKeyService.jwkToPem(key as any);
        setCachedKey(currentKid, pem, now + cacheTtlMs);

        if (kid) {
          if (currentKid === kid) {
            targetPem = pem;
          }
        } else if (!targetPem) {
          targetPem = pem;
        }
      } catch {
        // Bỏ qua key không hợp lệ
      }
    }

    if (!targetPem) {
      throw new Error(`Không tìm thấy Public Key phù hợp với kid: '${kid}'`);
    }

    return targetPem;
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Lấy Public Key từ cache hoặc fetch nếu hết hạn / chưa có
 */
async function getPublicKey(
  options: VerifyJwtLocallyOptions,
  kid?: string,
): Promise<string> {
  // 1. Nếu có publicKey tĩnh được cấu hình thủ công (Offline Mode)
  if (options.publicKey) {
    return options.publicKey;
  }

  const cacheKey = kid || JWKS_CONSTANTS.DEFAULT_KEY_ID;
  const cached = inMemoryKeyCache.get(cacheKey);

  // 2. Nếu có trong RAM và chưa hết hạn TTL 24h
  if (cached && cached.expiresAt > Date.now()) {
    return cached.pem;
  }

  const jwksUri = options.jwksUri || jwtConfig.authJwksUrl;

  // 3. Nếu có cấu hình JWKS URL: fetch từ remote endpoint
  if (jwksUri) {
    try {
      return await fetchPublicKeyFromJwks(
        jwksUri,
        kid,
        options.cacheTtlMs ?? JWKS_CONSTANTS.DEFAULT_CACHE_TTL_MS,
      );
    } catch (err) {
      // Nếu có cache cũ dù đã hết hạn thì fallback dùng tạm
      if (cached) {
        return cached.pem;
      }
      // Nếu options không chỉ định jwksUri riêng mà dùng jwtConfig.authJwksUrl từ env,
      // fallback an toàn về local JwtKeyService nếu local key khớp với kid
      if (!options.jwksUri) {
        const localKeyId = jwtKeyService.getKeyId();
        if (
          !kid ||
          kid === localKeyId ||
          kid === JWKS_CONSTANTS.DEFAULT_KEY_ID
        ) {
          const localPem = jwtKeyService.getPublicKeyPem();
          setCachedKey(
            cacheKey,
            localPem,
            Date.now() +
              (options.cacheTtlMs ?? JWKS_CONSTANTS.DEFAULT_CACHE_TTL_MS),
          );
          return localPem;
        }
      }
      throw err;
    }
  }

  // 4. Fallback về local JwtKeyService trong môi trường monolith
  const localPem = jwtKeyService.getPublicKeyPem();
  setCachedKey(
    cacheKey,
    localPem,
    Date.now() + (options.cacheTtlMs ?? JWKS_CONSTANTS.DEFAULT_CACHE_TTL_MS),
  );
  return localPem;
}

/**
 * Factory tạo middleware xác thực JWT phi tập trung (Decentralized Local Verification).
 * Cho phép mỗi microservice tự verify chữ ký token RS256 bằng Public Key trong 0.01ms
 * mà không cần gọi HTTP sang Auth Service.
 */
export function createVerifyJwtLocally(options: VerifyJwtLocallyOptions = {}) {
  const { optional = false, autoRefreshOnUnknownKid = true } = options;

  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    const token = extractTokenFromRequest(req);

    if (!token) {
      if (optional) {
        return next();
      }
      return next(new AppError("Unauthorized", 401, ERROR_CODE.UNAUTHORIZED));
    }

    const cleanPath = (
      (req.baseUrl || "") + (req.path || req.originalUrl || "")
    ).split("?")[0];
    const isStreamPath = cleanPath.endsWith("/stream");

    // Nếu là stream connection, ưu tiên verify bằng tempSecret dành cho short-lived SSE ticket
    if (isStreamPath) {
      try {
        const payload = jwt.verify(token, jwtConfig.tempSecret, {
          algorithms: [JWT_ALGORITHM.HS256],
        }) as AccessTokenClaims;

        if (payload.purpose === JWT_PURPOSE.SSE_STREAM_TICKET) {
          req.user = {
            id: payload.id,
            email: payload.email,
            role: payload.role as any,
            roleId: payload.roleId,
          };
          return next();
        }
      } catch {
        // Fallback sang accessSecret / RS256 bên dưới
      }
    }

    try {
      // 1. Phân tích header của token mà chưa verify chữ ký
      const decodedComplete = jwt.decode(token, { complete: true });
      if (!decodedComplete || !decodedComplete.header) {
        throw new AppError(
          "Invalid token format",
          401,
          ERROR_CODE.TOKEN_INVALID,
        );
      }

      const { alg, kid } = decodedComplete.header;

      // 2. Chặn các thuật toán không an toàn hoặc không được phép (chống Algorithm Confusion)
      if (alg !== JWT_ALGORITHM.RS256) {
        // Cho phép HS256 nếu có cấu hình tương thích ngược
        if (alg === JWT_ALGORITHM.HS256) {
          const payload = jwt.verify(token, jwtConfig.accessSecret, {
            algorithms: [JWT_ALGORITHM.HS256],
          }) as AccessTokenClaims;

          if (
            payload.purpose === JWT_PURPOSE.TWO_FACTOR ||
            payload.type === "TEMP" ||
            (payload.purpose &&
              payload.purpose !== JWT_PURPOSE.ACCESS &&
              (!isStreamPath || payload.purpose !== JWT_PURPOSE.SSE_STREAM_TICKET))
          ) {
            throw new AppError(
              "Token không hợp lệ để truy cập tài nguyên được bảo vệ",
              401,
              ERROR_CODE.UNAUTHORIZED,
            );
          }

          req.user = {
            id: payload.id,
            email: payload.email,
            role: payload.role as any,
            roleId: payload.roleId,
          };
          return next();
        }

        throw new AppError(
          `Thuật toán '${alg}' không được chấp nhận. Yêu cầu RS256.`,
          401,
          ERROR_CODE.TOKEN_INVALID,
        );
      }

      // 3. Lấy Public Key tương ứng với kid (từ cache 24h hoặc JWKS endpoint)
      let publicKey: string;
      try {
        publicKey = await getPublicKey(options, kid);
      } catch {
        throw new AppError(
          "Không tìm thấy khóa công khai để xác thực token",
          401,
          ERROR_CODE.TOKEN_INVALID,
        );
      }

      // 4. Xác thực chữ ký RS256 tại chỗ trong 0.01ms (kèm fallback refresh nếu key đã bị xoay vòng)
      let payload: AccessTokenClaims;
      try {
        payload = jwt.verify(token, publicKey, {
          algorithms: [JWT_ALGORITHM.RS256],
        }) as AccessTokenClaims;
      } catch (verifyErr) {
        const jwksUri = options.jwksUri || jwtConfig.authJwksUrl;
        if (kid && autoRefreshOnUnknownKid && jwksUri) {
          try {
            inMemoryKeyCache.delete(kid);
            const refreshedKey = await fetchPublicKeyFromJwks(
              jwksUri,
              kid,
              options.cacheTtlMs ?? JWKS_CONSTANTS.DEFAULT_CACHE_TTL_MS,
            );
            payload = jwt.verify(token, refreshedKey, {
              algorithms: [JWT_ALGORITHM.RS256],
            }) as AccessTokenClaims;
          } catch {
            throw verifyErr;
          }
        } else {
          throw verifyErr;
        }
      }

      // 5. Kiểm tra mục đích token (bảo vệ chống token tạm thời / 2FA)
      if (
        payload.purpose === JWT_PURPOSE.TWO_FACTOR ||
        payload.type === "TEMP" ||
        (payload.purpose &&
          payload.purpose !== JWT_PURPOSE.ACCESS &&
          (!isStreamPath || payload.purpose !== JWT_PURPOSE.SSE_STREAM_TICKET))
      ) {
        throw new AppError(
          "Token không hợp lệ để truy cập tài nguyên được bảo vệ",
          401,
          ERROR_CODE.UNAUTHORIZED,
        );
      }

      // 6. Gán context user cho microservice hiện tại
      req.user = {
        id: payload.id,
        email: payload.email,
        role: payload.role as any,
        roleId: payload.roleId,
      };

      next();
    } catch (error) {
      if (optional) {
        return next();
      }

      if (error instanceof AppError) {
        next(error);
      } else if (error instanceof jwt.TokenExpiredError) {
        next(new AppError("Token expired", 401, ERROR_CODE.TOKEN_EXPIRED));
      } else {
        next(new AppError("Invalid token", 401, ERROR_CODE.TOKEN_INVALID));
      }
    }
  };
}

/**
 * Middleware chuẩn mặc định cho Decentralized Local Verification
 */
export const verifyJwtLocally = createVerifyJwtLocally();

/**
 * Middleware tùy chọn (Optional Auth)
 */
export const optionalVerifyJwtLocally = createVerifyJwtLocally({
  optional: true,
});
