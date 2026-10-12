import crypto from "crypto";
import fs from "fs";
import path from "path";
import jwt from "jsonwebtoken";
import { jwtConfig } from "../../config/jwt.config";
import { envConfig } from "../../config/env.config";
import {
  JWT_ALGORITHM,
  JWKS_CONSTANTS,
  JwtAlgorithm,
} from "../constants/jwt.constant";
import { AppError } from "../errors/app-error";
import { ERROR_CODE } from "../errors/error-code";

export interface JwkKey {
  kty: string;
  use: string;
  alg: string;
  kid: string;
  n: string;
  e: string;
}

export interface JwksResponse {
  keys: JwkKey[];
}

export class JwtKeyService {
  private privateKeyPem: string = "";
  private publicKeyPem: string = "";
  private keyId: string = JWKS_CONSTANTS.DEFAULT_KEY_ID;
  private algorithm: JwtAlgorithm = JWT_ALGORITHM.RS256;
  private cachedJwk: JwkKey | null = null;

  constructor() {
    this.initKeys();
  }

  /**
   * Khởi tạo hoặc nạp cặp khóa RSA từ cấu hình môi trường / file hoặc tự động sinh.
   */
  public initKeys(): void {
    this.algorithm =
      jwtConfig.algorithm === JWT_ALGORITHM.HS256
        ? JWT_ALGORITHM.HS256
        : JWT_ALGORITHM.RS256;
    this.keyId = jwtConfig.keyId || JWKS_CONSTANTS.DEFAULT_KEY_ID;
    this.cachedJwk = null;

    let privateKey = this.resolveKeyString(jwtConfig.privateKey);
    let publicKey = this.resolveKeyString(jwtConfig.publicKey);

    // Kiểm tra file trên đĩa tại thư mục keys/ nếu chưa có trong env
    if (!privateKey) {
      const defaultPrivateKeyPath = path.resolve(
        process.cwd(),
        "keys",
        "private.key.pem",
      );
      if (fs.existsSync(defaultPrivateKeyPath)) {
        try {
          privateKey = fs.readFileSync(defaultPrivateKeyPath, "utf-8").trim();
        } catch {
          // Bỏ qua nếu không đọc được
        }
      }
    }

    if (!publicKey) {
      const defaultPublicKeyPath = path.resolve(
        process.cwd(),
        "keys",
        "public.key.pem",
      );
      if (fs.existsSync(defaultPublicKeyPath)) {
        try {
          publicKey = fs.readFileSync(defaultPublicKeyPath, "utf-8").trim();
        } catch {
          // Bỏ qua nếu không đọc được
        }
      }
    }

    // Nếu có private key nhưng chưa có public key, tự động trích xuất public key từ private key
    if (privateKey && !publicKey) {
      try {
        const pubKeyObj = crypto.createPublicKey(privateKey);
        publicKey = pubKeyObj
          .export({ type: "spki", format: "pem" })
          .toString()
          .trim();
      } catch {
        // Private key có thể không hợp lệ
      }
    }

    // Kiểm tra tính hợp lệ của cặp khóa RSA (tránh crash OpenSSL do cấu hình lỗi)
    let keysValid = false;
    if (privateKey && publicKey) {
      try {
        crypto.createPrivateKey(privateKey);
        crypto.createPublicKey(publicKey);
        keysValid = true;
      } catch {
        keysValid = false;
      }
    }

    // Nếu chưa có khóa hoặc khóa không hợp lệ: Tự động sinh cặp khóa RSA 2048-bit an toàn
    if (!keysValid) {
      const { publicKey: generatedPub, privateKey: generatedPriv } =
        crypto.generateKeyPairSync("rsa", {
          modulusLength: 2048,
          publicKeyEncoding: { type: "spki", format: "pem" },
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
        });

      privateKey = generatedPriv.trim();
      publicKey = generatedPub.trim();
    }

    this.privateKeyPem = privateKey;
    this.publicKeyPem = publicKey;
  }

  /**
   * Giải quyết chuỗi khóa từ định dạng raw PEM, escaped newline, base64 hoặc đường dẫn file.
   */
  private resolveKeyString(rawKey?: string): string {
    if (!rawKey || typeof rawKey !== "string") return "";
    let trimmed = rawKey.trim();
    if (!trimmed) return "";

    // Xử lý escaped newlines trong .env file (\\n -> \n)
    if (trimmed.includes("\\n")) {
      trimmed = trimmed.replace(/\\n/g, "\n");
    }

    // Nếu là định dạng PEM trực tiếp
    if (trimmed.includes("-----BEGIN")) {
      return trimmed;
    }

    // Kiểm tra xem có phải là đường dẫn file hợp lệ không
    try {
      const resolvedPath = path.isAbsolute(trimmed)
        ? trimmed
        : path.resolve(process.cwd(), trimmed);
      if (fs.existsSync(resolvedPath)) {
        return fs.readFileSync(resolvedPath, "utf-8").trim();
      }
    } catch {
      // Không phải file path
    }

    // Thử giải mã Base64
    try {
      const decoded = Buffer.from(trimmed, "base64").toString("utf-8");
      if (decoded.includes("-----BEGIN")) {
        return decoded.trim();
      }
    } catch {
      // Không phải base64 hợp lệ
    }

    return trimmed;
  }

  public getAlgorithm(): JwtAlgorithm {
    return this.algorithm;
  }

  public getKeyId(): string {
    return this.keyId;
  }

  public getPrivateKeyPem(): string {
    return this.privateKeyPem;
  }

  public getPublicKeyPem(): string {
    return this.publicKeyPem;
  }

  /**
   * Sinh JWK (JSON Web Key) chuẩn RFC 7517 từ Public Key RSA
   */
  public getJwk(): JwkKey {
    if (this.cachedJwk) {
      return this.cachedJwk;
    }

    const keyObj = crypto.createPublicKey(this.publicKeyPem);
    const exported = keyObj.export({ format: "jwk" }) as {
      kty?: string;
      n?: string;
      e?: string;
    };

    this.cachedJwk = {
      kty: exported.kty || JWKS_CONSTANTS.KEY_TYPE,
      use: JWKS_CONSTANTS.KEY_USE,
      alg: JWT_ALGORITHM.RS256,
      kid: this.keyId,
      n: exported.n || "",
      e: exported.e || "AQAB",
    };

    return this.cachedJwk;
  }

  /**
   * Trả về JWKS (JSON Web Key Set) RFC 7517 cho endpoint /.well-known/jwks.json
   */
  public getJwks(): JwksResponse {
    return {
      keys: [this.getJwk()],
    };
  }

  /**
   * Chuyển đổi một JWK thành định dạng PEM Public Key (dùng cho offline verification)
   */
  public static jwkToPem(jwk: JwkKey | Record<string, unknown>): string {
    const keyObject = crypto.createPublicKey({
      key: jwk as any,
      format: "jwk",
    });
    return keyObject.export({ type: "spki", format: "pem" }).toString().trim();
  }

  /**
   * Ký Access Token bằng thuật toán cấu hình (mặc định RS256 với RSA Private Key)
   */
  public signAccessToken(
    payload: string | Buffer | object,
    options?: jwt.SignOptions,
  ): string {
    if (this.algorithm === JWT_ALGORITHM.RS256) {
      return jwt.sign(payload, this.privateKeyPem, {
        algorithm: JWT_ALGORITHM.RS256,
        keyid: this.keyId,
        expiresIn: (options?.expiresIn ||
          jwtConfig.accessExpiresIn) as jwt.SignOptions["expiresIn"],
        ...options,
      });
    }

    // Fallback sang HS256 nếu cấu hình chỉ định
    return jwt.sign(payload, jwtConfig.accessSecret, {
      algorithm: JWT_ALGORITHM.HS256,
      expiresIn: (options?.expiresIn ||
        jwtConfig.accessExpiresIn) as jwt.SignOptions["expiresIn"],
      ...options,
    });
  }

  /**
   * Xác thực Access Token linh hoạt (hỗ trợ cả RS256 và HS256)
   */
  public verifyAccessToken<T = unknown>(
    token: string,
    options?: jwt.VerifyOptions,
  ): T {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header) {
      throw new AppError("Invalid token format", 401, ERROR_CODE.TOKEN_INVALID);
    }

    const alg = decoded.header.alg;

    if (alg === JWT_ALGORITHM.RS256) {
      return jwt.verify(token, this.publicKeyPem, {
        algorithms: [JWT_ALGORITHM.RS256],
        ...options,
      }) as T;
    }

    if (alg === JWT_ALGORITHM.HS256) {
      return jwt.verify(token, jwtConfig.accessSecret, {
        algorithms: [JWT_ALGORITHM.HS256],
        ...options,
      }) as T;
    }

    throw new AppError(
      `Thuật toán ký token '${alg}' không được hỗ trợ`,
      401,
      ERROR_CODE.TOKEN_INVALID,
    );
  }

  /**
   * Phương thức hỗ trợ testing: Gán khóa tùy chỉnh (phục vụ mô phỏng rotation / rogue key)
   */
  public setCustomKeys(
    privateKeyPem: string,
    publicKeyPem: string,
    keyId?: string,
  ): void {
    this.privateKeyPem = privateKeyPem;
    this.publicKeyPem = publicKeyPem;
    if (keyId) this.keyId = keyId;
    this.cachedJwk = null;
  }
}

export const jwtKeyService = new JwtKeyService();
