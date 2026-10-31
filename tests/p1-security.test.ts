process.env.NODE_ENV = "test";
import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import jwt from "jsonwebtoken";
import { FileService } from "../src/modules/files/file.service";
import {
  createVerifyJwtLocally,
} from "../src/middlewares/verify-jwt-locally.middleware";
import {
  authMiddleware,
  extractTokenFromRequest,
} from "../src/middlewares/auth.middleware";
import {
  createRequireGatewayOrigin,
  requireGatewayOrigin,
} from "../src/middlewares/request-id.middleware";
import {
  createRateLimiter,
  normalizeRateLimitPrefix,
} from "../src/middlewares/rate-limit.middleware";
import {
  FILE_RECORDS_FTS_VECTOR_EXPR,
  FileRepository,
} from "../src/modules/files/file.repository";
import { getMasterKeyBuffer } from "../src/common/helpers/crypto.helper";
import { parseTrustProxy, resolveEncryptionKey } from "../src/config/env.config";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { MEDIA_LIMITS } from "../src/common/constants/media.constant";
import { uploadImageMiddleware } from "../src/middlewares/upload.middleware";
import {
  startOutboxRelay,
  stopOutboxRelay,
  handleMediaShutdown,
  resetShutdownStateForTesting,
} from "../src/server";
import { eventBus } from "../src/common/services/event-bus.service";

describe("P1 Security Vulnerabilities Patch Verification (SEC-05 - SEC-27)", { concurrency: false }, () => {
  let rsaPrivateKey: string;
  let rsaPublicKey: string;

  before(() => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    rsaPrivateKey = privateKey;
    rsaPublicKey = publicKey;

    (jwtKeyService as any).publicKeyPem = rsaPublicKey;
    (jwtKeyService as any).privateKeyPem = rsaPrivateKey;
  });

  describe("SEC-05: confirmUpload verifies object storage existence and actual size via HeadObject", () => {
    test("rejects confirmation when object does not exist in storage", async () => {
      const mockRepo: any = {
        findById: async () => ({
          id: "file-uuid-1",
          userId: "user-1",
          bucketKey: "images/user-1/test.png",
          isConfirmed: false,
        }),
      };

      const mockR2: any = {
        headObject: async () => ({
          size: 0,
          exists: false,
        }),
      };

      const service = new FileService(mockRepo, mockR2, {} as any, {} as any);

      await assert.rejects(
        async () => {
          await service.confirmUpload(
            "file-uuid-1",
            { size: 500 },
            "user-1",
            [PERMISSIONS.FILE_UPLOAD],
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.NOT_FOUND);
          assert.ok(err.message.includes("chưa được tải lên hệ thống lưu trữ"));
          return true;
        },
      );
    });

    test("rejects confirmation when actual storage size exceeds maximum allowed limit", async () => {
      const mockRepo: any = {
        findById: async () => ({
          id: "file-uuid-2",
          userId: "user-1",
          bucketKey: "images/user-1/huge.bin",
          isConfirmed: false,
        }),
      };

      const mockR2: any = {
        headObject: async () => ({
          size: 150 * 1024 * 1024, // 150MB actual size in storage
          exists: true,
        }),
      };

      const service = new FileService(mockRepo, mockR2, {} as any, {} as any);

      // Client attempts to spoof size as only 100 bytes
      await assert.rejects(
        async () => {
          await service.confirmUpload(
            "file-uuid-2",
            { size: 100 },
            "user-1",
            [PERMISSIONS.FILE_UPLOAD],
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          assert.ok(err.message.includes("Dung lượng tệp thực tế"));
          return true;
        },
      );
    });

    test("records actual storage size in database rather than spoofed client size", async () => {
      let recordedSize: number | undefined;

      const mockRepo: any = {
        findById: async () => ({
          id: "file-uuid-3",
          userId: "user-1",
          bucketKey: "images/user-1/valid.png",
          isConfirmed: false,
          isPublic: false,
        }),
        confirmUpload: async (_id: string, size?: number) => {
          recordedSize = size;
          return {
            id: "file-uuid-3",
            size,
            isConfirmed: true,
            isPublic: false,
            bucketKey: "images/user-1/valid.png",
          };
        },
        createAuditLog: async () => {},
      };

      const mockR2: any = {
        headObject: async () => ({
          size: 2048500, // 2MB actual size
          exists: true,
        }),
        getPublicUrl: () => "https://r2/valid.png",
      };

      const service = new FileService(mockRepo, mockR2, {} as any, {} as any);

      // Client sends spoofed reported size 50
      const result = await service.confirmUpload(
        "file-uuid-3",
        { size: 50 },
        "user-1",
        [PERMISSIONS.FILE_UPLOAD],
      );

      assert.strictEqual(recordedSize, 2048500, "Database must store actual size from HeadObject");
      assert.strictEqual(result.size, 2048500);
    });
  });

  describe("SEC-06: Dockerfile enforces frozen lockfile and copies public key into runner stage", () => {
    test("verifies Dockerfile contains frozen lockfile and public key copy instructions", () => {
      const dockerfilePath = path.resolve(__dirname, "..", "Dockerfile");
      const content = fs.readFileSync(dockerfilePath, "utf-8");

      // Verify pnpm-lock.yaml and frozen-lockfile in Stage 1 (deps)
      assert.ok(
        content.includes("COPY package.json pnpm-lock.yaml* ./"),
        "Stage 1 must copy pnpm-lock.yaml",
      );
      assert.ok(
        content.includes("pnpm install --frozen-lockfile"),
        "Stage 1 must enforce --frozen-lockfile",
      );

      // Verify public key is copied into Stage 3 (runner)
      assert.ok(
        content.includes("COPY --chown=node:node --from=builder /app/keys/public.key.pem* ./keys/"),
        "Stage 3 must copy keys/public.key.pem into runner",
      );
    });
  });

  describe("SEC-07: Decentralized token verification enforces mustChangePassword claim", () => {
    test("verifyJwtLocally rejects token with mustChangePassword: true with 403 FORBIDDEN", async () => {
      const token = jwt.sign(
        {
          id: "temp-user-id",
          email: "user@test.local",
          role: "USER",
          purpose: "ACCESS",
          mustChangePassword: true,
        },
        rsaPrivateKey,
        { algorithm: "RS256" },
      );

      const middleware = createVerifyJwtLocally({
        publicKey: rsaPublicKey,
      });

      const req: any = {
        headers: { authorization: `Bearer ${token}` },
      };
      const res: any = {};
      let caughtError: any = null;

      await middleware(req, res, (err: any) => {
        caughtError = err;
      });

      assert.ok(caughtError instanceof AppError);
      assert.strictEqual(caughtError.statusCode, 403);
      assert.strictEqual(caughtError.code, ERROR_CODE.FORBIDDEN);
      assert.ok(caughtError.message.includes("Yêu cầu đổi mật khẩu"));
    });

    test("verifyJwtLocally allows token when mustChangePassword is not set", async () => {
      const token = jwt.sign(
        {
          id: "normal-user-id",
          email: "normal@test.local",
          role: "USER",
          purpose: "ACCESS",
        },
        rsaPrivateKey,
        { algorithm: "RS256" },
      );

      const middleware = createVerifyJwtLocally({
        publicKey: rsaPublicKey,
      });

      const req: any = {
        headers: { authorization: `Bearer ${token}` },
      };
      const res: any = {};
      let nextCalled = false;

      await middleware(req, res, (err: any) => {
        assert.ifError(err);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true);
      assert.ok(req.user);
      assert.strictEqual(req.user.id, "normal-user-id");
    });

    test("authMiddleware rejects token with mustChangePassword: true with 403 FORBIDDEN", async () => {
      const token = jwt.sign(
        {
          id: "temp-user-id-2",
          email: "user2@test.local",
          role: "USER",
          purpose: "ACCESS",
          mustChangePassword: true,
        },
        rsaPrivateKey,
        { algorithm: "RS256" },
      );

      const req: any = {
        headers: { authorization: `Bearer ${token}` },
      };
      const res: any = {};
      let caughtError: any = null;

      await authMiddleware(req, res, (err: any) => {
        caughtError = err;
      });

      assert.ok(caughtError instanceof AppError);
      assert.strictEqual(caughtError.statusCode, 403);
      assert.strictEqual(caughtError.code, ERROR_CODE.FORBIDDEN);
    });
  });

  describe("SEC-08: parseTrustProxy restricts proxy trust to 1 hop preventing IP spoofing", () => {
    test("returns 1 for 'true' to trust only 1 Traefik Ingress hop", () => {
      const result = parseTrustProxy("true");
      assert.strictEqual(result, 1, "Must return 1 hop rather than boolean true");
    });

    test("returns false for 'false'", () => {
      const result = parseTrustProxy("false");
      assert.strictEqual(result, false);
    });

    test("parses numeric string hop count correctly", () => {
      assert.strictEqual(parseTrustProxy("2"), 2);
      assert.strictEqual(parseTrustProxy("3"), 3);
    });

    test("parses comma-separated list of trusted subnets", () => {
      const result = parseTrustProxy("127.0.0.1, 10.0.0.0/8");
      assert.deepStrictEqual(result, ["127.0.0.1", "10.0.0.0/8"]);
    });
  });

  describe("SEC-09: requireGatewayOrigin Middleware Enforces Trusted API Gateway Origin", () => {
    test("rejects request when secret is configured and header x-gateway-secret is missing", () => {
      const middleware = createRequireGatewayOrigin("super-secret-gateway-token");
      const req: any = { headers: {} };
      const res: any = {};
      let caughtError: any = null;

      middleware(req, res, (err: any) => {
        caughtError = err;
      });

      assert.ok(caughtError instanceof AppError);
      assert.strictEqual(caughtError.statusCode, 403);
      assert.strictEqual(caughtError.code, ERROR_CODE.GATEWAY_REQUIRED);
    });

    test("rejects request when header x-gateway-secret does not match configured secret", () => {
      const middleware = createRequireGatewayOrigin("super-secret-gateway-token");
      const req: any = { headers: { "x-gateway-secret": "wrong-secret-token" } };
      const res: any = {};
      let caughtError: any = null;

      middleware(req, res, (err: any) => {
        caughtError = err;
      });

      assert.ok(caughtError instanceof AppError);
      assert.strictEqual(caughtError.statusCode, 403);
      assert.strictEqual(caughtError.code, ERROR_CODE.GATEWAY_REQUIRED);
    });

    test("allows request when header x-gateway-secret matches configured secret", () => {
      const middleware = createRequireGatewayOrigin("super-secret-gateway-token");
      const req: any = { headers: { "x-gateway-secret": "super-secret-gateway-token" } };
      const res: any = {};
      let nextCalled = false;

      middleware(req, res, (err?: any) => {
        assert.strictEqual(err, undefined);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true);
    });

    test("allows request when secret is empty (backward compatibility fallback)", () => {
      const middleware = createRequireGatewayOrigin("");
      const req: any = { headers: {} };
      const res: any = {};
      let nextCalled = false;

      middleware(req, res, (err?: any) => {
        assert.strictEqual(err, undefined);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true);
    });
  });

  describe("SEC-10: Token Extraction Rejects Bearer JWTs in Query Parameters", () => {
    test("extractTokenFromRequest ignores query parameters even on download paths", () => {
      const req: any = {
        baseUrl: "/api/v1/files",
        path: "/123/download",
        query: { token: "secret-jwt-in-query", ticket: "sse-ticket-in-query" },
        headers: {},
        cookies: {},
      };

      const extracted = extractTokenFromRequest(req);
      assert.strictEqual(extracted, undefined, "Must not extract token from query parameters");
    });

    test("extractTokenFromRequest extracts token from Authorization Bearer header", () => {
      const req: any = {
        headers: { authorization: "Bearer valid-bearer-token" },
        cookies: {},
        query: {},
      };

      const extracted = extractTokenFromRequest(req);
      assert.strictEqual(extracted, "valid-bearer-token");
    });

    test("extractTokenFromRequest extracts token from accessToken cookie", () => {
      const req: any = {
        headers: {},
        cookies: { accessToken: "valid-cookie-token" },
        query: {},
      };

      const extracted = extractTokenFromRequest(req);
      assert.strictEqual(extracted, "valid-cookie-token");
    });

    test("authMiddleware rejects request with query parameter token with 400 VALIDATION_ERROR", async () => {
      const req: any = {
        query: { token: "leaked-token-in-query" },
        headers: {},
        cookies: {},
      };
      const res: any = {};
      let caughtError: any = null;

      await authMiddleware(req, res, (err: any) => {
        caughtError = err;
      });

      assert.ok(caughtError instanceof AppError);
      assert.strictEqual(caughtError.statusCode, 400);
      assert.strictEqual(caughtError.code, ERROR_CODE.VALIDATION_ERROR);
    });

    test("verifyJwtLocally rejects request with query parameter ticket with 400 VALIDATION_ERROR", async () => {
      const middleware = createVerifyJwtLocally();
      const req: any = {
        query: { ticket: "leaked-ticket-in-query" },
        headers: {},
        cookies: {},
      };
      const res: any = {};
      let caughtError: any = null;

      await middleware(req, res, (err: any) => {
        caughtError = err;
      });

      assert.ok(caughtError instanceof AppError);
      assert.strictEqual(caughtError.statusCode, 400);
      assert.strictEqual(caughtError.code, ERROR_CODE.VALIDATION_ERROR);
    });
  });

  describe("SEC-11: uploadImageMiddleware Enforces Direct RAM Memory Buffer Limits", () => {
    test("verifies MEDIA_LIMITS.MAX_DIRECT_IMAGE_BYTES is 10MB (10485760 bytes)", () => {
      assert.strictEqual(MEDIA_LIMITS.MAX_DIRECT_IMAGE_BYTES, 10 * 1024 * 1024);
    });

    test("verifies uploadImageMiddleware limits fileSize to MAX_DIRECT_IMAGE_BYTES and files to 1", () => {
      const limits = (uploadImageMiddleware as any).limits;
      assert.ok(limits, "Multer limits must be configured");
      assert.strictEqual(limits.fileSize, 10 * 1024 * 1024, "fileSize limit must be 10MB");
      assert.strictEqual(limits.files, 1, "files limit must be 1 file to prevent memory exhaustion");
      assert.strictEqual(limits.fields, 10, "fields limit must be bounded");
    });
  });

  describe("SEC-12: Transactional Outbox Relay Background Worker", () => {
    test("startOutboxRelay starts recurring interval and handleMediaShutdown executes drain", async () => {
      let relayCalled = false;
      const originalRelay = eventBus.relayPendingOutboxEvents;
      try {
        (eventBus as any).relayPendingOutboxEvents = async (batchSize: number) => {
          relayCalled = true;
          return 3;
        };

        const timer = startOutboxRelay(15, 25);
        assert.ok(timer, "Timer must be returned");

        for (let i = 0; i < 25 && !relayCalled; i++) {
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        assert.strictEqual(relayCalled, true, "relayPendingOutboxEvents should have been called");
      } finally {
        stopOutboxRelay();
        (eventBus as any).relayPendingOutboxEvents = originalRelay;
      }

      // Test stopOutboxRelay
      const timer2 = startOutboxRelay(1000);
      assert.ok(timer2);
      stopOutboxRelay();
      stopOutboxRelay();

      // Test handleMediaShutdown drain
      let drained = false;
      const originalClose = eventBus.close;
      try {
        resetShutdownStateForTesting();
        (eventBus as any).relayPendingOutboxEvents = async () => {
          drained = true;
          return 5;
        };
        (eventBus as any).close = async () => {};

        await handleMediaShutdown("SIGTERM");
        assert.strictEqual(drained, true, "Outbox drain should execute during shutdown");
      } finally {
        resetShutdownStateForTesting();
        (eventBus as any).relayPendingOutboxEvents = originalRelay;
        (eventBus as any).close = originalClose;
      }
    });
  });

  describe("SEC-25: Dual Mount Route Prefix Rate Limit Normalization", () => {
    test("normalizeRateLimitPrefix normalizes dual mount routes /api/v1/files and /files to the same prefix", () => {
      assert.strictEqual(
        normalizeRateLimitPrefix({ baseUrl: "/api/v1/files" } as any),
        "/api/v1/files",
      );
      assert.strictEqual(
        normalizeRateLimitPrefix({ baseUrl: "/files" } as any),
        "/api/v1/files",
      );
      assert.strictEqual(
        normalizeRateLimitPrefix({ originalUrl: "/files/123/download" } as any),
        "/api/v1/files",
      );
      assert.strictEqual(
        normalizeRateLimitPrefix({ originalUrl: "/api/v1/files/upload" } as any),
        "/api/v1/files",
      );
      assert.strictEqual(
        normalizeRateLimitPrefix({ baseUrl: "/other" } as any),
        "/other",
      );
    });

    test("rate limiter shares quota across /api/v1/files and /files preventing 2x quota dilution", () => {
      const limiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 2,
      });

      const res: any = {
        statusCode: 200,
        headers: {} as Record<string, any>,
        setHeader(name: string, val: any) {
          this.headers[name] = val;
        },
        status(code: number) {
          this.statusCode = code;
          return this;
        },
        json(body: any) {
          this.body = body;
          return this;
        },
      };

      let req1Next = false;
      limiter({ ip: "192.168.1.50", baseUrl: "/api/v1/files" } as any, res, () => {
        req1Next = true;
      });
      assert.strictEqual(req1Next, true, "Req 1 should pass");

      let req2Next = false;
      limiter({ ip: "192.168.1.50", baseUrl: "/files" } as any, res, () => {
        req2Next = true;
      });
      assert.strictEqual(req2Next, true, "Req 2 should pass");

      let req3Next = false;
      limiter({ ip: "192.168.1.50", baseUrl: "/files" } as any, res, () => {
        req3Next = true;
      });
      assert.strictEqual(req3Next, false, "Req 3 should be blocked");
      assert.strictEqual(res.statusCode, 429, "Req 3 must receive HTTP 429");
      assert.strictEqual(res.body.code, ERROR_CODE.RATE_LIMIT_EXCEEDED);
    });
  });

  describe("SEC-26: Full-Text Search GIN Expression Centralization", () => {
    test("verifies FILE_RECORDS_FTS_VECTOR_EXPR matches exact to_tsvector expression", () => {
      assert.ok(FILE_RECORDS_FTS_VECTOR_EXPR);
      const sqlText =
        (FILE_RECORDS_FTS_VECTOR_EXPR as any).text ||
        (FILE_RECORDS_FTS_VECTOR_EXPR as any).strings?.join("");
      assert.ok(
        sqlText.includes("to_tsvector('simple'"),
        "Must contain to_tsvector with simple dictionary",
      );
      assert.ok(
        sqlText.includes("coalesce(f.original_name, '')"),
        "Must concatenate original_name",
      );
      assert.ok(
        sqlText.includes("coalesce(f.file_name, '')"),
        "Must concatenate file_name",
      );
      assert.ok(
        sqlText.includes("coalesce(f.folder, '')"),
        "Must concatenate folder",
      );
    });

    test("verifies migration file exists with idx_file_records_fts GIN index", () => {
      const migrationDir = path.join(
        __dirname,
        "../prisma/migrations/20261014160000_add_file_records_full_text_search_gin_index",
      );
      const migrationFile = path.join(migrationDir, "migration.sql");
      assert.ok(fs.existsSync(migrationFile), "Migration SQL file must exist");
      const content = fs.readFileSync(migrationFile, "utf8");
      assert.ok(
        content.includes("CREATE INDEX IF NOT EXISTS \"idx_file_records_fts\""),
      );
      assert.ok(content.includes("USING gin"));
    });
  });

  describe("SEC-27: Cryptography Helper and Environment Config Hardcoded Fallback Master Key Elimination", () => {
    const originalEnv = { ...process.env };

    test("getMasterKeyBuffer throws an error in production when ENCRYPTION_KEY and APP_SECRET are missing", () => {
      try {
        process.env.NODE_ENV = "production";
        delete process.env.ENCRYPTION_KEY;
        delete process.env.APP_SECRET;

        assert.throws(
          () => {
            getMasterKeyBuffer();
          },
          (err: any) => {
            assert.ok(err instanceof Error);
            assert.ok(
              err.message.includes(
                "ENCRYPTION_KEY or APP_SECRET must be explicitly configured in production",
              ),
            );
            return true;
          },
        );
      } finally {
        process.env = { ...originalEnv };
      }
    });

    test("getMasterKeyBuffer succeeds when customKey is provided", () => {
      const buf = getMasterKeyBuffer(
        "my-custom-32-chars-long-secure-key-phrase",
      );
      assert.ok(Buffer.isBuffer(buf));
      assert.strictEqual(buf.length, 32);
    });

    test("resolveEncryptionKey throws in production when key is absent or too short", () => {
      try {
        process.env.NODE_ENV = "production";
        delete process.env.ENCRYPTION_KEY;
        delete process.env.APP_SECRET;

        assert.throws(
          () => {
            resolveEncryptionKey();
          },
          (err: any) => {
            assert.ok(err instanceof Error);
            assert.ok(
              err.message.includes(
                "must be explicitly configured with at least 32 characters in production",
              ),
            );
            return true;
          },
        );
      } finally {
        process.env = { ...originalEnv };
      }
    });
  });
});
