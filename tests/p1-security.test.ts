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
import { jwtConfig } from "../src/config/jwt.config";
import { JWT_PURPOSE } from "../src/common/constants/jwt.constant";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { ROLES } from "../src/common/constants/role.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { EVENT_NAMES } from "../src/common/constants/event.constant";
import { MEDIA_LIMITS } from "../src/common/constants/media.constant";
import { R2Service } from "../src/common/services/r2.service";
import { uploadImageMiddleware } from "../src/middlewares/upload.middleware";
import { requireAnyPermission } from "../src/middlewares/permission.middleware";
import fileRouter from "../src/modules/files/file.route";
import { cleanupFilesSchema } from "../src/modules/files/file.validation";
import {
  startOutboxRelay,
  stopOutboxRelay,
  handleMediaShutdown,
  resetShutdownStateForTesting,
} from "../src/server";
import {
  errorMiddleware,
  maskSensitiveCredentials,
  sanitizeErrorForLogging,
} from "../src/middlewares/error.middleware";
import { eventBus, SENSITIVE_OUTBOX_FIELDS } from "../src/common/services/event-bus.service";

describe("P1 Security Vulnerabilities Patch Verification (SEC-05 - SEC-50)", { concurrency: false }, () => {
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

  describe("SEC-28: Confirm Upload Route Mounts Permission Guard", () => {
    test("verifies POST /:id/confirm route is registered with permission middleware", () => {
      const confirmLayer = (fileRouter as any).stack.find(
        (l: any) => l.route && l.route.path === "/:id/confirm" && l.route.methods.post,
      );
      assert.ok(confirmLayer, "Route POST /:id/confirm must be defined");
      assert.ok(
        confirmLayer.route.stack.length >= 5,
        `Expected at least 5 middleware handlers, got ${confirmLayer.route.stack.length}`,
      );
    });

    test("requireAnyPermission(FILE_UPLOAD, FILE_MANAGE) blocks user without required permissions", () => {
      const middleware = requireAnyPermission(
        PERMISSIONS.FILE_UPLOAD,
        PERMISSIONS.FILE_MANAGE,
      );
      const req: any = {
        user: { id: "user-1", role: ROLES.USER, permissions: [] },
      };
      let caughtError: any;
      middleware(req, {} as any, (err?: any) => {
        caughtError = err;
      });
      assert.ok(caughtError instanceof AppError);
      assert.strictEqual(caughtError.statusCode, 403);
      assert.strictEqual(caughtError.code, ERROR_CODE.FORBIDDEN);
    });

    test("requireAnyPermission(FILE_UPLOAD, FILE_MANAGE) permits user with FILE_UPLOAD", () => {
      const middleware = requireAnyPermission(
        PERMISSIONS.FILE_UPLOAD,
        PERMISSIONS.FILE_MANAGE,
      );
      const req: any = {
        user: { id: "user-1", role: ROLES.USER, permissions: [PERMISSIONS.FILE_UPLOAD] },
      };
      let nextCalled = false;
      middleware(req, {} as any, (err?: any) => {
        assert.strictEqual(err, undefined);
        nextCalled = true;
      });
      assert.strictEqual(nextCalled, true);
    });
  });

  describe("SEC-29: Orphan File Cleanup Schema & Service Enforce Retention Lower Bound", () => {
    test("cleanupFilesSchema rejects softDeletedRetentionDays < 30 (e.g. 1 or 29)", () => {
      const parsed1 = cleanupFilesSchema.safeParse({ softDeletedRetentionDays: 1 });
      assert.strictEqual(parsed1.success, false);
      if (!parsed1.success) {
        assert.ok(parsed1.error.issues.some((i) => i.path.includes("softDeletedRetentionDays")));
      }

      const parsed29 = cleanupFilesSchema.safeParse({ softDeletedRetentionDays: 29 });
      assert.strictEqual(parsed29.success, false);
    });

    test("cleanupFilesSchema accepts default or softDeletedRetentionDays >= 30", () => {
      const parsedDefault = cleanupFilesSchema.safeParse({});
      assert.strictEqual(parsedDefault.success, true);
      if (parsedDefault.success) {
        assert.strictEqual(parsedDefault.data.softDeletedRetentionDays, 30);
        assert.strictEqual(parsedDefault.data.unconfirmedMaxAgeHours, 24);
      }

      const parsed60 = cleanupFilesSchema.safeParse({ softDeletedRetentionDays: 60 });
      assert.strictEqual(parsed60.success, true);
    });

    test("FileService.cleanupOrphanFiles throws AppError if softDeletedRetentionDays < 30", async () => {
      const service = new FileService({} as any, {} as any, {} as any, {} as any);
      await assert.rejects(
        async () => {
          await service.cleanupOrphanFiles(24, 10);
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          assert.ok(err.message.includes("tối thiểu là 30 ngày"));
          return true;
        },
      );
    });
  });

  describe("SEC-30: Role and Permission Synchronization Between Controller and Service", () => {
    test("Administrator with role ADMIN and empty permissions array can access private file owned by another user", async () => {
      const mockRepo: any = {
        findById: async () => ({
          id: "file-private-1",
          userId: "other-user-99",
          isPublic: false,
          bucketKey: "private/other/doc.pdf",
        }),
      };
      const mockR2: any = {
        getPublicUrl: () => "https://r2/doc.pdf",
      };
      const service = new FileService(mockRepo, mockR2, {} as any, {} as any);

      // Admin caller with role ADMIN and empty permissions
      const file = await service.getFileById(
        "file-private-1",
        "admin-user-id",
        [],
        ROLES.ADMIN,
      );
      assert.strictEqual(file.id, "file-private-1");
      assert.strictEqual(file.userId, "other-user-99");
    });

    test("Regular user without FILE_MANAGE cannot access private file owned by another user", async () => {
      const mockRepo: any = {
        findById: async () => ({
          id: "file-private-2",
          userId: "other-user-99",
          isPublic: false,
          bucketKey: "private/other/doc.pdf",
        }),
      };
      const service = new FileService(mockRepo, {} as any, {} as any, {} as any);

      await assert.rejects(
        async () => {
          await service.getFileById(
            "file-private-2",
            "normal-user-id",
            [],
            ROLES.USER,
          );
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          return true;
        },
      );
    });

    test("Administrator with role ADMIN and empty permissions can delete any file", async () => {
      let deletedId = "";
      const mockRepo: any = {
        findById: async () => ({
          id: "file-del-1",
          userId: "other-user-99",
          bucketKey: "files/other.pdf",
          fileName: "other.pdf",
        }),
        delete: async (id: string) => {
          deletedId = id;
          return { id };
        },
        createAuditLog: async () => {},
      };
      const mockR2: any = {
        deleteFile: async () => {},
      };
      const service = new FileService(mockRepo, mockR2, {} as any, {} as any);

      await service.deleteFile(
        "file-del-1",
        "admin-user-id",
        [],
        undefined,
        ROLES.ADMIN,
      );
      assert.strictEqual(deletedId, "file-del-1");
    });

    test("Administrator with role ADMIN and empty permissions can list all files without ownership restriction", async () => {
      let passedCanManageAll: boolean | undefined;
      const mockRepo: any = {
        findAll: async (_query: any, _userId: any, canManageAll: boolean) => {
          passedCanManageAll = canManageAll;
          return { data: [], meta: { total: 0, page: 1, limit: 10 } };
        },
      };
      const service = new FileService(mockRepo, {} as any, {} as any, {} as any);

      await service.listFiles({}, "admin-id", [], ROLES.ADMIN);
      assert.strictEqual(passedCanManageAll, true);
    });
  });

  describe("SEC-38: Unchecked S3 Object Stream Concatenation Triggers V8 Heap OOM DoS", () => {
    test("R2Service.getObjectBuffer rejects when ContentLength exceeds maxBufferBytes", async () => {
      const r2Service = new R2Service();
      (r2Service as any).client = {
        send: async () => ({
          ContentLength: 30 * 1024 * 1024, // 30MB
          Body: {
            destroy: () => {},
            async *[Symbol.asyncIterator]() {
              yield Buffer.alloc(1024);
            },
          },
        }),
      };

      await assert.rejects(
        async () => {
          await r2Service.getObjectBuffer("test-key", 25 * 1024 * 1024);
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          assert.ok(err.message.includes("vượt quá giới hạn bộ nhớ đệm cho phép"));
          return true;
        },
      );
    });

    test("R2Service.getObjectBuffer rejects when stream chunks accumulate beyond limit", async () => {
      const r2Service = new R2Service();
      let streamDestroyed = false;
      (r2Service as any).client = {
        send: async () => ({
          Body: {
            destroy: () => {
              streamDestroyed = true;
            },
            async *[Symbol.asyncIterator]() {
              yield Buffer.alloc(10 * 1024);
              yield Buffer.alloc(10 * 1024);
              yield Buffer.alloc(10 * 1024); // Total 30KB > 25KB
            },
          },
        }),
      };

      await assert.rejects(
        async () => {
          await r2Service.getObjectBuffer("test-key", 25 * 1024);
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          assert.ok(err.message.includes("vượt quá giới hạn bộ nhớ đệm cho phép"));
          assert.strictEqual(streamDestroyed, true);
          return true;
        },
      );
    });

    test("R2Service.getObjectBuffer succeeds when stream is within maxBufferBytes", async () => {
      const r2Service = new R2Service();
      (r2Service as any).client = {
        send: async () => ({
          ContentLength: 4,
          Body: {
            async *[Symbol.asyncIterator]() {
              yield Buffer.from("test");
            },
          },
        }),
      };

      const buf = await r2Service.getObjectBuffer("test-key", 1024);
      assert.strictEqual(buf.toString(), "test");
    });

    test("FileService.transformExistingImage propagates AppError when storage buffer exceeds limit", async () => {
      const mockRepo: any = {
        findById: async () => ({
          id: "img-1",
          mimeType: "image/jpeg",
          bucketKey: "images/img-1.jpg",
          isPublic: true,
        }),
      };
      const mockR2: any = {
        getObjectBuffer: async () => {
          throw new AppError("Dung lượng tệp tin vượt quá giới hạn bộ nhớ đệm cho phép", 400, ERROR_CODE.VALIDATION_ERROR);
        },
      };
      const mockProcessor: any = {
        isSupportedImageMime: () => true,
      };
      const service = new FileService(mockRepo, mockR2, {} as any, mockProcessor);

      await assert.rejects(
        async () => {
          await service.transformExistingImage("img-1", {});
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          assert.ok(err.message.includes("vượt quá giới hạn bộ nhớ đệm"));
          return true;
        },
      );
    });
  });

  describe("SEC-39: Direct Image Upload Endpoint Dispatches Domain Event for AI Inspection", () => {
    test("FileService.uploadAndProcessImage publishes file.created event upon successful direct upload", async () => {
      let publishedEventName = "";
      let publishedPayload: any = null;

      const mockRepo: any = {
        createDirectFile: async (data: any) => ({
          id: "direct-file-1",
          userId: data.userId,
          fileName: data.fileName,
          originalName: data.originalName,
          mimeType: data.mimeType,
          size: data.size,
          bucketKey: data.bucketKey,
          folder: data.folder,
          isPublic: data.isPublic,
          metadata: data.metadata,
        }),
        createAuditLog: async () => {},
      };

      const mockR2: any = {
        uploadBuffer: async () => {},
        getPublicUrl: () => "https://r2/img.webp",
      };

      const mockEventBus: any = {
        publish: async (name: string, payload: any) => {
          publishedEventName = name;
          publishedPayload = payload;
        },
      };

      const mockProcessor: any = {
        processImage: async () => ({
          buffer: Buffer.from("webp-data"),
          info: { format: "webp", width: 800, height: 600, size: 2048, mimeType: "image/webp" },
        }),
      };

      const service = new FileService(mockRepo, mockR2, mockEventBus, mockProcessor);

      const result = await service.uploadAndProcessImage(
        {
          buffer: Buffer.from("fake-jpg"),
          originalname: "inspection.jpg",
          mimetype: "image/jpeg",
          size: 5000,
        },
        { folder: "inspections", isPublic: true },
        "safety-officer-1",
        [PERMISSIONS.FILE_UPLOAD],
      );

      assert.strictEqual(result.id, "direct-file-1");
      assert.strictEqual(publishedEventName, EVENT_NAMES.FILE_CREATED);
      assert.strictEqual(publishedPayload.fileId, "direct-file-1");
      assert.strictEqual(publishedPayload.fileName, result.fileName);
      assert.strictEqual(publishedPayload.mimeType, "image/webp");
      assert.strictEqual(publishedPayload.size, 2048);
    });
  });

  describe("SEC-40: File Deletion Pipeline Dispatches file.deleted Domain Event", () => {
    test("FileService.deleteFile publishes file.deleted event with metadata", async () => {
      let publishedEventName = "";
      let publishedPayload: any = null;

      const mockRepo: any = {
        findById: async () => ({
          id: "file-to-delete-1",
          userId: "user-1",
          bucketKey: "images/user-1/evidence.png",
          fileName: "evidence.png",
        }),
        delete: async () => {},
        createAuditLog: async () => {},
      };

      const mockR2: any = {
        deleteFile: async () => {},
      };

      const mockEventBus: any = {
        publish: async (name: string, payload: any) => {
          publishedEventName = name;
          publishedPayload = payload;
        },
      };

      const service = new FileService(mockRepo, mockR2, mockEventBus, {} as any);

      await service.deleteFile(
        "file-to-delete-1",
        "user-1",
        [PERMISSIONS.FILE_DELETE],
      );

      assert.strictEqual(publishedEventName, EVENT_NAMES.FILE_DELETED);
      assert.strictEqual(publishedPayload.fileId, "file-to-delete-1");
      assert.strictEqual(publishedPayload.bucketKey, "images/user-1/evidence.png");
      assert.strictEqual(publishedPayload.actorId, "user-1");
      assert.ok(publishedPayload.deletedAt);
    });
  });

  describe("SEC-41: Two-Phase Cleanup Coordinates Database and Storage Deletion", () => {
    test("FileService.cleanupOrphanFiles executes markCleanupPending before R2 deletion and hardDeleteMany after", async () => {
      const callSequence: string[] = [];

      const mockRepo: any = {
        findUnconfirmedOlderThan: async () => [
          { id: "unconfirmed-1", bucketKey: "orphans/unconfirmed-1.bin" },
        ],
        markCleanupPending: async (ids: string[]) => {
          callSequence.push(`markCleanupPending:${ids.join(",")}`);
          return { count: ids.length };
        },
        hardDeleteMany: async (ids: string[]) => {
          callSequence.push(`hardDeleteMany:${ids.join(",")}`);
          return { count: ids.length };
        },
        findSoftDeletedOlderThan: async () => [],
        createAuditLog: async () => {},
      };

      const mockR2: any = {
        deleteFiles: async (keys: string[]) => {
          callSequence.push(`r2DeleteFiles:${keys.join(",")}`);
          return { deleted: keys, errors: [] };
        },
      };

      const service = new FileService(mockRepo, mockR2, {} as any, {} as any);

      const result = await service.cleanupOrphanFiles(24, 30);
      assert.strictEqual(result.unconfirmedCleaned, 1);
      assert.deepStrictEqual(callSequence, [
        "markCleanupPending:unconfirmed-1",
        "r2DeleteFiles:orphans/unconfirmed-1.bin",
        "hardDeleteMany:unconfirmed-1",
      ]);
    });
  });

  describe("SEC-45: 64-Bit BigInt Storage and Safe JSON Serialization for Large Media Files", () => {
    test("BigInt.prototype.toJSON safely serializes BigInt to Number in JSON.stringify", () => {
      const largeFilePayload = {
        id: "media-video-1",
        size: BigInt(5368709120), // 5GB > 2.14GB 32-bit limit
      };
      const jsonStr = JSON.stringify(largeFilePayload);
      const parsed = JSON.parse(jsonStr);
      assert.strictEqual(parsed.size, 5368709120);
      assert.strictEqual(typeof parsed.size, "number");
    });

    test("FileRepository maps Prisma BigInt size to Number to preserve API compatibility", async () => {
      const mockPrismaFileRecord = {
        create: async (args: any) => ({
          id: "record-1",
          userId: args.data.userId,
          originalName: args.data.originalName,
          fileName: args.data.fileName,
          mimeType: args.data.mimeType,
          size: args.data.size,
          bucketKey: args.data.bucketKey,
          folder: args.data.folder,
          isPublic: args.data.isPublic,
          isConfirmed: false,
          checksum: null,
          metadata: null,
          createdAt: new Date(),
          updatedAt: new Date(),
          deletedAt: null,
        }),
        findFirst: async () => ({
          id: "record-1",
          originalName: "large_cctv.mp4",
          fileName: "large_cctv.mp4",
          mimeType: "video/mp4",
          size: BigInt(5368709120),
          bucketKey: "videos/large_cctv.mp4",
          folder: "videos",
          isPublic: false,
          isConfirmed: true,
          userId: "user-1",
          checksum: null,
          metadata: null,
          createdAt: new Date(),
          updatedAt: new Date(),
          deletedAt: null,
        }),
        update: async (args: any) => ({
          id: args.where.id,
          originalName: "large_cctv.mp4",
          fileName: "large_cctv.mp4",
          mimeType: "video/mp4",
          size: args.data.size ?? BigInt(0),
          bucketKey: "videos/large_cctv.mp4",
          folder: "videos",
          isPublic: false,
          isConfirmed: true,
          userId: "user-1",
          checksum: null,
          metadata: null,
          createdAt: new Date(),
          updatedAt: new Date(),
          deletedAt: null,
        }),
      };

      const repo = new FileRepository({ fileRecord: mockPrismaFileRecord } as any);
      // Test repository handles BigInt size and returns Number
      const created = await repo.create({
        originalName: "large_cctv.mp4",
        fileName: "large_cctv.mp4",
        mimeType: "video/mp4",
        size: 5368709120,
        bucketKey: "videos/large_cctv.mp4",
      });
      assert.strictEqual(created.size, 5368709120);
      assert.strictEqual(typeof created.size, "number");

      const found = await repo.findById("record-1");
      assert.ok(found);
      assert.strictEqual(found.size, 5368709120);
      assert.strictEqual(typeof found.size, "number");

      const confirmed = await repo.confirmUpload("record-1", BigInt(6000000000));
      assert.strictEqual(confirmed.size, 6000000000);
      assert.strictEqual(typeof confirmed.size, "number");
    });
  });

  describe("SEC-46: Decentralized JWT Verification Extracts RFC 7519 sub Claim", () => {
    test("verifyJwtLocally resolves sub claim to req.user.id when id is omitted", async () => {
      const token = jwt.sign(
        {
          sub: "user-fed-sub-999",
          email: "federated@example.com",
          role: ROLES.SAFETY_OFFICER,
          permissions: [PERMISSIONS.FILE_READ],
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
      assert.strictEqual(req.user.id, "user-fed-sub-999");
      assert.strictEqual(req.user.email, "federated@example.com");
    });

    test("verifyJwtLocally extracts sub claim for SSE stream ticket", async () => {
      const ticket = jwt.sign(
        {
          sub: "sse-user-sub-111",
          email: "sse@example.com",
          role: ROLES.SAFETY_OFFICER,
          permissions: [PERMISSIONS.FILE_READ],
          purpose: JWT_PURPOSE.SSE_STREAM_TICKET,
        },
        jwtConfig.tempSecret,
        { algorithm: "HS256" },
      );

      const middleware = createVerifyJwtLocally({
        publicKey: rsaPublicKey,
      });

      const req: any = {
        path: "/stream",
        headers: { authorization: `Bearer ${ticket}` },
      };
      const res: any = {};
      let nextCalled = false;

      await middleware(req, res, (err: any) => {
        assert.ifError(err);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true);
      assert.ok(req.user);
      assert.strictEqual(req.user.id, "sse-user-sub-111");
    });
  });

  describe("SEC-47: Outbox Event Payload Encryption Whitelist Protects S3 Presigned URLs and Media Tokens", () => {
    test("SENSITIVE_OUTBOX_FIELDS includes presignedUrl, uploadUrl, downloadUrl, accessKey, secretAccessKey, sessionToken, token, apiKey", () => {
      const requiredFields = [
        "presignedUrl",
        "uploadUrl",
        "downloadUrl",
        "accessKey",
        "secretAccessKey",
        "sessionToken",
        "token",
        "apiKey",
      ];
      for (const field of requiredFields) {
        assert.ok(
          (SENSITIVE_OUTBOX_FIELDS as readonly string[]).includes(field),
          `SENSITIVE_OUTBOX_FIELDS must include ${field}`,
        );
      }
    });

    test("encryptSensitivePayloadFields encrypts all sensitive media tokens and presigned URLs with enc: prefix", () => {
      const sensitivePayload = {
        fileId: "file-xyz",
        presignedUrl: "https://r2.cloudflarestorage.com/bucket/key?X-Amz-Signature=secret123",
        uploadUrl: "https://upload.service/target",
        downloadUrl: "https://download.service/target?token=secret",
        accessKey: "AKIAIOSFODNN7EXAMPLE",
        secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        sessionToken: "session-token-abc",
        token: "bearer-token-xyz",
        apiKey: "api-secret-key-123",
      };

      const encrypted = eventBus.encryptSensitivePayloadFields(sensitivePayload);

      assert.strictEqual(encrypted.fileId, "file-xyz");
      assert.ok(encrypted.presignedUrl.startsWith("enc:"), "presignedUrl must be encrypted");
      assert.ok(encrypted.uploadUrl.startsWith("enc:"), "uploadUrl must be encrypted");
      assert.ok(encrypted.downloadUrl.startsWith("enc:"), "downloadUrl must be encrypted");
      assert.ok(encrypted.accessKey.startsWith("enc:"), "accessKey must be encrypted");
      assert.ok(encrypted.secretAccessKey.startsWith("enc:"), "secretAccessKey must be encrypted");
      assert.ok(encrypted.sessionToken.startsWith("enc:"), "sessionToken must be encrypted");
      assert.ok(encrypted.token.startsWith("enc:"), "token must be encrypted");
      assert.ok(encrypted.apiKey.startsWith("enc:"), "apiKey must be encrypted");

      const decrypted = eventBus.decryptSensitivePayloadFields(encrypted);
      assert.deepStrictEqual(decrypted, sensitivePayload, "Decrypted payload must match original");
    });
  });

  describe("SEC-48: S3 Batch Deletion Inspects Errors to Prevent Leaking Storage Blobs", () => {
    test("R2Service.deleteFiles throws AppError 500 when S3 returns response.Errors", async () => {
      const r2Service = new R2Service();
      (r2Service as any).client = {
        send: async () => ({
          Errors: [
            {
              Key: "orphans/file-1.bin",
              Code: "AccessDenied",
              Message: "Access Denied by bucket policy",
            },
          ],
        }),
      };

      await assert.rejects(
        async () => {
          await r2Service.deleteFiles(["orphans/file-1.bin"]);
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 500);
          assert.strictEqual(err.code, ERROR_CODE.INTERNAL_SERVER_ERROR);
          assert.ok(err.message.includes("S3 batch deletion partial failure"));
          assert.ok(err.message.includes("orphans/file-1.bin"));
          return true;
        },
      );
    });

    test("FileService.cleanupOrphanFiles preserves DB records when R2Service.deleteFiles throws on S3 errors", async () => {
      let hardDeleteCalled = false;
      const mockRepo: any = {
        findUnconfirmedOlderThan: async () => [
          { id: "orphan-id-1", bucketKey: "orphans/file-1.bin" },
        ],
        markCleanupPending: async () => ({ count: 1 }),
        hardDeleteMany: async () => {
          hardDeleteCalled = true;
          return { count: 1 };
        },
        findSoftDeletedOlderThan: async () => [],
        createAuditLog: async () => {},
      };

      const mockR2: any = {
        deleteFiles: async () => {
          throw new AppError("S3 batch deletion partial failure", 500, ERROR_CODE.INTERNAL_SERVER_ERROR);
        },
      };

      const service = new FileService(mockRepo, mockR2, {} as any, {} as any);
      const result = await service.cleanupOrphanFiles(24, 30);

      assert.strictEqual(result.unconfirmedCleaned, 0);
      assert.strictEqual(hardDeleteCalled, false, "hardDeleteMany must NOT be called when R2 batch deletion fails");
    });
  });

  describe("SEC-49: Unhandled Error Credential Masking and Log Sanitization", () => {
    test("maskSensitiveCredentials masks database connection strings and passwords", () => {
      const postgresErr =
        "Can't reach database server at postgresql://media_user:SuperSecretP@ssword123!@localhost:5433/ppe_media_db";
      const masked = maskSensitiveCredentials(postgresErr);
      assert.ok(!masked.includes("SuperSecretP@ssword123!"));
      assert.ok(masked.includes("postgresql://media_user:***@localhost:5433/ppe_media_db"));

      const redisErr = "Redis auth error on redis://:RedisTopSecretKey@redis-server:6379/0";
      const maskedRedis = maskSensitiveCredentials(redisErr);
      assert.ok(!maskedRedis.includes("RedisTopSecretKey"));
      assert.ok(maskedRedis.includes("redis://:***@redis-server:6379/0"));
    });

    test("maskSensitiveCredentials masks AWS S3 presigned signatures and tokens", () => {
      const s3Url =
        "https://r2.cloudflarestorage.com/ppe-bucket/photo.jpg?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20261101/auto/s3/aws4_request&X-Amz-Signature=d2c88f1234567890abcdef&X-Amz-Security-Token=AQoDYXdzEJr...";
      const masked = maskSensitiveCredentials(s3Url);
      assert.ok(!masked.includes("d2c88f1234567890abcdef"));
      assert.ok(!masked.includes("AKIAIOSFODNN7EXAMPLE"));
      assert.ok(masked.includes("X-Amz-Signature=***"));
      assert.ok(masked.includes("X-Amz-Credential=***"));
      assert.ok(masked.includes("X-Amz-Security-Token=***"));
    });

    test("maskSensitiveCredentials masks Bearer tokens and sensitive key-value pairs", () => {
      const logText =
        'Failed auth with Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc and secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" and password: "SecretPassword"';
      const masked = maskSensitiveCredentials(logText);
      assert.ok(!masked.includes("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"));
      assert.ok(!masked.includes("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
      assert.ok(!masked.includes("SecretPassword"));
      assert.ok(masked.includes("Bearer ***"));
      assert.ok(masked.includes('secretAccessKey: "***"'));
      assert.ok(masked.includes('password: "***"'));
    });

    test("sanitizeErrorForLogging returns structured error with masked message and stack", () => {
      const rawError = new Error(
        "PrismaClientInitializationError: Connection error postgresql://media_admin:MyP@ssw0rd!@127.0.0.1:5433/ppe_media_db",
      );
      rawError.stack =
        "Error: Connection error postgresql://media_admin:MyP@ssw0rd!@127.0.0.1:5433/ppe_media_db\n    at PrismaClient.connect (/app/db.ts:12:15)";

      const sanitized = sanitizeErrorForLogging(rawError);
      assert.strictEqual(sanitized.name, "Error");
      assert.ok(!sanitized.message.includes("MyP@ssw0rd!"));
      assert.ok(sanitized.message.includes("postgresql://media_admin:***@127.0.0.1:5433/ppe_media_db"));
      assert.ok(sanitized.stack);
      assert.ok(!sanitized.stack.includes("MyP@ssw0rd!"));
      assert.ok(sanitized.stack.includes("postgresql://media_admin:***@127.0.0.1:5433/ppe_media_db"));
    });

    test("errorMiddleware masks credentials when logging unhandled error to console.error", () => {
      const loggedArgs: any[] = [];
      const origConsoleError = console.error;
      console.error = (...args: any[]) => {
        loggedArgs.push(args);
      };

      try {
        const sensitiveError = new Error(
          "AWS CredentialsProviderError: accessKeyId: AKIAIOSFODNN7EXAMPLE, secretAccessKey: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
        const req: any = {
          headers: { "x-request-id": "req-safe-123" },
        };
        const res: any = {
          statusCode: 200,
          status(code: number) {
            this.statusCode = code;
            return this;
          },
          json(body: any) {
            this.body = body;
            return this;
          },
        };

        errorMiddleware(sensitiveError, req, res, () => {});

        assert.strictEqual(res.statusCode, 500);
        assert.strictEqual(res.body.code, ERROR_CODE.INTERNAL_SERVER_ERROR);
        assert.strictEqual(loggedArgs.length, 1);

        const logOutput = JSON.stringify(loggedArgs[0]);
        assert.ok(!logOutput.includes("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        assert.ok(logOutput.includes("secretAccessKey"));
      } finally {
        console.error = origConsoleError;
      }
    });
  });

  describe("SEC-50: Distributed Event Deduplication via Redis SET NX EX and Multi-Pod Idempotency", () => {
    test("tryAcquireEventLock uses Redis SET NX EX and prevents duplicate execution across replicas", async () => {
      const redisStore = new Map<string, string>();
      const mockRedis: any = {
        set: async (key: string, val: string, exFlag: string, ttl: number, nxFlag?: string) => {
          if (nxFlag === "NX" && redisStore.has(key)) {
            return null; // Key already exists -> NX fails
          }
          redisStore.set(key, val);
          return "OK";
        },
        get: async (key: string) => redisStore.get(key) || null,
        del: async (...keys: string[]) => {
          for (const k of keys) redisStore.delete(k);
          return keys.length;
        },
        keys: async (pattern: string) => Array.from(redisStore.keys()),
      };

      const originalRedis = (eventBus as any).redisConnection;
      const originalAvailable = (eventBus as any).isRedisAvailable;

      try {
        (eventBus as any).setRedisConnectionForTesting(mockRedis, true);

        // First attempt for event 'evt-uuid-1' must acquire lock successfully
        const firstAttempt = await eventBus.tryAcquireEventLock("evt-uuid-1", 60000);
        assert.strictEqual(firstAttempt, true, "First event delivery must acquire lock");

        // Second attempt for the same event ID across any pod must be rejected as duplicate
        const secondAttempt = await eventBus.tryAcquireEventLock("evt-uuid-1", 60000);
        assert.strictEqual(secondAttempt, false, "Second event delivery must be rejected as duplicate");

        // Verify isEventAlreadyProcessed queries Redis key
        const isProcessed = await eventBus.isEventAlreadyProcessed("evt-uuid-1");
        assert.strictEqual(isProcessed, true, "isEventAlreadyProcessed must confirm key in Redis");

        // Verify clearProcessedCache clears keys from Redis
        await eventBus.clearProcessedCache();
        const afterClear = await eventBus.isEventAlreadyProcessed("evt-uuid-1");
        assert.strictEqual(afterClear, false, "Cache clear must remove Redis idempotency keys");
      } finally {
        (eventBus as any).setRedisConnectionForTesting(originalRedis, originalAvailable);
      }
    });

    test("dispatchDirectly skips duplicate execution when event is already recorded in Redis", async () => {
      const redisStore = new Map<string, string>();
      redisStore.set("idempotency:event:evt-dup-999", "1"); // Already processed by another replica

      const mockRedis: any = {
        get: async (key: string) => redisStore.get(key) || null,
        set: async (key: string, val: string) => {
          redisStore.set(key, val);
          return "OK";
        },
        del: async (...keys: string[]) => {
          for (const k of keys) redisStore.delete(k);
          return keys.length;
        },
        keys: async () => Array.from(redisStore.keys()),
      };

      let handlerCalled = false;
      const originalRedis = (eventBus as any).redisConnection;
      const originalAvailable = (eventBus as any).isRedisAvailable;
      let unsubscribe: (() => void) | undefined;

      try {
        (eventBus as any).setRedisConnectionForTesting(mockRedis, true);
        unsubscribe = (eventBus as any).subscribe(EVENT_NAMES.FILE_DELETED, async () => {
          handlerCalled = true;
        });

        await eventBus.dispatchDirectly({
          id: "evt-dup-999",
          name: EVENT_NAMES.FILE_DELETED,
          timestamp: Date.now(),
          source: "smart-ppe-media-service",
          payload: { fileId: "f-1" },
        } as any);

        assert.strictEqual(handlerCalled, false, "Handler must NOT be executed for duplicate event from Redis");
      } finally {
        if (unsubscribe) unsubscribe();
        (eventBus as any).setRedisConnectionForTesting(originalRedis, originalAvailable);
        await eventBus.clearProcessedCache();
      }
    });

    test("isEventAlreadyProcessed falls back safely to in-memory cache when Redis is unavailable", async () => {
      const originalRedis = (eventBus as any).redisConnection;
      const originalAvailable = (eventBus as any).isRedisAvailable;

      try {
        (eventBus as any).setRedisConnectionForTesting(undefined, false);
        await eventBus.clearProcessedCache();

        const notProcessed = await eventBus.isEventAlreadyProcessed("inmem-evt-1");
        assert.strictEqual(notProcessed, false);

        await eventBus.markEventProcessed("inmem-evt-1");
        const processed = await eventBus.isEventAlreadyProcessed("inmem-evt-1");
        assert.strictEqual(processed, true);
      } finally {
        (eventBus as any).setRedisConnectionForTesting(originalRedis, originalAvailable);
        await eventBus.clearProcessedCache();
      }
    });
  });
});
