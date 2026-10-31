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
import { eventBus } from "../src/common/services/event-bus.service";

describe("P1 Security Vulnerabilities Patch Verification (SEC-05 - SEC-41)", { concurrency: false }, () => {
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
});
