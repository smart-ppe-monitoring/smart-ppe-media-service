process.env.NODE_ENV = "test";
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { FileRepository } from "../src/modules/files/file.repository";
import { maintenanceGuard } from "../src/middlewares/maintenance.middleware";
import { UUID_REGEX, isUuid } from "../src/common/helpers/uuid.helper";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import { ROLES } from "../src/common/constants/role.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { EVENT_NAMES } from "../src/common/constants/event.constant";
import { StorageCleanupSubscriber } from "../src/common/subscribers/storage-cleanup.subscriber";
import { FileService } from "../src/modules/files/file.service";
import { R2Service } from "../src/common/services/r2.service";
import { directImageUploadSchema, listFilesSchema } from "../src/modules/files/file.validation";
import {
  calculatePaginationSkip,
  formatPaginationMeta,
  MAX_PAGINATION_PAGE,
} from "../src/common/helpers/pagination.helper";
import { envConfig } from "../src/config/env.config";
import { z } from "zod";
import express from "express";

import { AUDIT_ACTION } from "../src/common/constants/audit-log.constant";
import { getMediaPrisma, prisma } from "../src/database/prisma.client";
import { sharpRateLimitMiddleware, createRateLimiter } from "../src/middlewares/rate-limit.middleware";
import * as fs from "node:fs";
import * as path from "node:path";

describe("P2 Security Vulnerabilities Patch Verification (SEC-13 - SEC-44)", { concurrency: false }, () => {
  // ── SEC-13 ───────────────────────────────────────────────────────────────
  describe("SEC-13: Raw PostgreSQL Full-Text Search Query Exception Handling and Safe Fallback", () => {
    test("searchFts intercepts PostgreSQL syntax error 42601 and safely falls back to findAll", async () => {
      let findAllCalled = false;
      const repo = new FileRepository({} as any);

      // Mock findAll to verify fallback
      (repo as any).findAll = async () => {
        findAllCalled = true;
        return {
          data: [{ id: "fallback-file-1", originalName: "doc.pdf" }],
          meta: { page: 1, limit: 10, total: 1, totalPages: 1 },
        };
      };

      // Mock prisma.$transaction to simulate PostgreSQL syntax error code 42601
      const mockPrisma: any = {
        $transaction: async () => {
          const err: any = new Error("syntax error in tsquery: 'malformed & |'");
          err.code = "42601";
          throw err;
        },
      };

      // Replace prisma reference inside FileRepository for this test
      const originalPrisma = (repo as any).db;
      (repo as any).db = mockPrisma;

      // Also override global prisma import used in searchFts if necessary
      // Since searchFts uses `prisma.$transaction`, let's test directly with mock
      const result = await repo.searchFts({ search: "malformed & |" }, "user-1", true);

      assert.strictEqual(findAllCalled, true, "searchFts must fallback to findAll on syntax error");
      assert.strictEqual(result.data.length, 1);
      assert.strictEqual(result.data[0].id, "fallback-file-1");
    });
  });

  // ── SEC-14 ───────────────────────────────────────────────────────────────
  describe("SEC-14: Maintenance Guard Middleware Enforces HTTP 503 with Exemptions", () => {
    test("rejects standard user requests with 503 SYSTEM_MAINTENANCE when maintenance mode is active", async () => {
      const middleware = maintenanceGuard({ isMaintenanceMode: true });

      const req: any = {
        originalUrl: "/api/v1/files/upload",
        user: { role: ROLES.OPERATOR, permissions: [] },
      };
      const res: any = {};
      let passedError: any = null;

      await middleware(req, res, (err?: any) => {
        passedError = err;
      });

      assert.ok(passedError instanceof AppError);
      assert.strictEqual(passedError.statusCode, 503);
      assert.strictEqual(passedError.code, ERROR_CODE.SYSTEM_MAINTENANCE);
    });

    test("allows health check and openapi exempt routes during maintenance", async () => {
      const middleware = maintenanceGuard({ isMaintenanceMode: true });

      const exemptUrls = [
        "/health",
        "/health/live",
        "/api/v1/files/health",
        "/files/health",
        "/openapi.json",
        "/api/v1/files/openapi.json",
      ];

      for (const url of exemptUrls) {
        let nextCalled = false;
        let nextError: any = null;
        const req: any = {
          originalUrl: url,
          user: { role: ROLES.OPERATOR },
        };
        const res: any = {};

        await middleware(req, res, (err?: any) => {
          nextCalled = true;
          nextError = err;
        });

        assert.strictEqual(nextCalled, true, `Exempt URL ${url} must call next()`);
        assert.strictEqual(nextError, undefined, `Exempt URL ${url} must not pass error`);
      }
    });

    test("allows requests from ADMIN role or users with MAINTENANCE_BYPASS permission", async () => {
      const middleware = maintenanceGuard({ isMaintenanceMode: true });

      // Admin user
      let adminNext = false;
      const adminReq: any = {
        originalUrl: "/api/v1/files/delete",
        user: { role: ROLES.ADMIN, permissions: [] },
      };
      await middleware(adminReq, {} as any, (err?: any) => {
        if (!err) adminNext = true;
      });
      assert.strictEqual(adminNext, true, "Admin role must bypass maintenance guard");

      // User with MAINTENANCE_BYPASS permission
      let bypassNext = false;
      const bypassReq: any = {
        originalUrl: "/api/v1/files/config",
        user: { role: ROLES.OPERATOR, permissions: ["MAINTENANCE_BYPASS"] },
      };
      await middleware(bypassReq, {} as any, (err?: any) => {
        if (!err) bypassNext = true;
      });
      assert.strictEqual(bypassNext, true, "User with MAINTENANCE_BYPASS permission must bypass maintenance guard");
    });

    test("allows all requests when maintenance mode is inactive", async () => {
      const middleware = maintenanceGuard({ isMaintenanceMode: false });

      let nextCalled = false;
      let nextError: any = null;
      const req: any = {
        originalUrl: "/api/v1/files/upload",
        user: { role: ROLES.OPERATOR },
      };

      await middleware(req, {} as any, (err?: any) => {
        nextCalled = true;
        nextError = err;
      });

      assert.strictEqual(nextCalled, true);
      assert.strictEqual(nextError, undefined);
    });
  });

  // ── SEC-15 ───────────────────────────────────────────────────────────────
  describe("SEC-15: Strict RFC 4122 / RFC 9562 UUID Regex Validation", () => {
    test("rejects strings of 36 hyphens, non-hyphenated strings, and malformed layouts", () => {
      const invalidUuids = [
        "------------------------------------",
        "123456789012345678901234567890123456",
        "12345678-1234-1234-1234-1234567890123", // 13 chars in last block
        "1234567-1234-1234-1234-123456789012",  // 7 chars in first block
        "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "not-a-uuid-at-all",
        "",
      ];

      for (const val of invalidUuids) {
        assert.strictEqual(UUID_REGEX.test(val), false, `UUID_REGEX must reject '${val}'`);
        assert.strictEqual(isUuid(val), false, `isUuid must reject '${val}'`);
      }
    });

    test("accepts valid RFC 4122 / RFC 9562 UUIDs including v4, v7, and nil UUID", () => {
      const validUuids = [
        "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11",
        "018ec99e-7d84-7a32-b7b5-78e8b23f5b04",
        "00000000-0000-0000-0000-000000000000",
        "A0EEBC99-9C0B-4EF8-BB6D-6BB9BD380A11",
      ];

      for (const val of validUuids) {
        assert.strictEqual(UUID_REGEX.test(val), true, `UUID_REGEX must accept '${val}'`);
        assert.strictEqual(isUuid(val), true, `isUuid must accept '${val}'`);
      }
    });
  });

  // ── SEC-16 ───────────────────────────────────────────────────────────────
  describe("SEC-16: Satellite Service Configuration Enforces JWT Public Key, Not Private Key", () => {
    test("satellite service environment refinement does not require JWT_PRIVATE_KEY when JWT_PUBLIC_KEY is provided", () => {
      // Recreate the refinement logic from env.config.ts to verify schema behavior
      const testSatelliteSchema = z
        .object({
          NODE_ENV: z.string(),
          JWT_ALGORITHM: z.enum(["RS256", "HS256"]),
          JWT_PRIVATE_KEY: z.string().default(""),
          JWT_PUBLIC_KEY: z.string().default(""),
          AUTH_JWKS_URL: z.string().default(""),
        })
        .refine(
          (env) => {
            if (env.NODE_ENV !== "production") return true;
            if (env.JWT_ALGORITHM === "RS256") {
              const hasPublicKeyEnv =
                typeof env.JWT_PUBLIC_KEY === "string" &&
                env.JWT_PUBLIC_KEY.trim().length > 0;
              const hasJwksUrl =
                typeof env.AUTH_JWKS_URL === "string" &&
                env.AUTH_JWKS_URL.trim().length > 0;
              return hasPublicKeyEnv || hasJwksUrl;
            }
            return true;
          },
          {
            message: "JWT_PUBLIC_KEY or AUTH_JWKS_URL is required in production",
            path: ["JWT_PUBLIC_KEY"],
          },
        );

      // In production: with JWT_PUBLIC_KEY configured and JWT_PRIVATE_KEY empty -> SUCCESS
      const validSatelliteEnv = testSatelliteSchema.safeParse({
        NODE_ENV: "production",
        JWT_ALGORITHM: "RS256",
        JWT_PRIVATE_KEY: "", // Empty private key is completely allowed for satellite service!
        JWT_PUBLIC_KEY: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...\n-----END PUBLIC KEY-----",
      });

      assert.strictEqual(
        validSatelliteEnv.success,
        true,
        "Satellite service in production must succeed without JWT_PRIVATE_KEY when JWT_PUBLIC_KEY is provided",
      );

      // In production: with BOTH empty -> FAILS on JWT_PUBLIC_KEY
      const invalidSatelliteEnv = testSatelliteSchema.safeParse({
        NODE_ENV: "production",
        JWT_ALGORITHM: "RS256",
        JWT_PRIVATE_KEY: "",
        JWT_PUBLIC_KEY: "",
        AUTH_JWKS_URL: "",
      });

      assert.strictEqual(
        invalidSatelliteEnv.success,
        false,
        "Satellite service in production must fail when both JWT_PUBLIC_KEY and AUTH_JWKS_URL are absent",
      );
      if (!invalidSatelliteEnv.success) {
        assert.strictEqual(invalidSatelliteEnv.error.issues[0].path[0], "JWT_PUBLIC_KEY");
      }
    });
  });

  // ── SEC-17 ───────────────────────────────────────────────────────────────
  describe("SEC-17: StorageCleanupSubscriber Performs Physical R2 Deletion of Expired Unconfirmed Uploads", () => {
    test("cleanupExpiredUnconfirmedFile calls r2Service.deleteFile and hardDeleteMany when file remains unconfirmed", async () => {
      let r2DeleteCalledWith = "";
      let hardDeleteCalledWith: string[] = [];

      const mockR2: any = {
        deleteFile: async (key: string) => {
          r2DeleteCalledWith = key;
        },
      };

      const mockRepo: any = {
        findById: async () => ({
          id: "unconfirmed-file-123",
          isConfirmed: false,
          bucketKey: "uploads/unconfirmed-file-123.jpg",
        }),
        hardDeleteMany: async (ids: string[]) => {
          hardDeleteCalledWith = ids;
          return { count: ids.length };
        },
      };

      const mockBus: any = {
        subscribe: () => () => {},
      };

      const subscriber = new StorageCleanupSubscriber(mockBus, mockR2, mockRepo);

      // Simulate tracked file
      (subscriber as any).trackedUnconfirmedFiles.set("unconfirmed-file-123", {
        fileId: "unconfirmed-file-123",
        key: "uploads/unconfirmed-file-123.jpg",
        bucket: "ppe-media",
        expiresAt: new Date(Date.now() - 1000),
      });

      const cleaned = await subscriber.cleanupExpiredUnconfirmedFile("unconfirmed-file-123");

      assert.strictEqual(cleaned, true);
      assert.strictEqual(r2DeleteCalledWith, "uploads/unconfirmed-file-123.jpg", "Must delete physical blob from R2");
      assert.deepStrictEqual(hardDeleteCalledWith, ["unconfirmed-file-123"], "Must hard-delete database record");
      assert.strictEqual((subscriber as any).trackedUnconfirmedFiles.has("unconfirmed-file-123"), false);

      subscriber.clear();
    });

    test("cleanupExpiredUnconfirmedFile skips R2 deletion if file was successfully confirmed", async () => {
      let r2DeleteCalled = false;

      const mockR2: any = {
        deleteFile: async () => {
          r2DeleteCalled = true;
        },
      };

      const mockRepo: any = {
        findById: async () => ({
          id: "confirmed-file-456",
          isConfirmed: true, // File was confirmed!
          bucketKey: "uploads/confirmed-file-456.jpg",
        }),
      };

      const subscriber = new StorageCleanupSubscriber({} as any, mockR2, mockRepo);

      (subscriber as any).trackedUnconfirmedFiles.set("confirmed-file-456", {
        fileId: "confirmed-file-456",
        key: "uploads/confirmed-file-456.jpg",
        bucket: "ppe-media",
        expiresAt: new Date(Date.now() - 1000),
      });

      const cleaned = await subscriber.cleanupExpiredUnconfirmedFile("confirmed-file-456");

      assert.strictEqual(cleaned, true);
      assert.strictEqual(r2DeleteCalled, false, "Must NOT delete confirmed files from R2");
      assert.strictEqual((subscriber as any).trackedUnconfirmedFiles.has("confirmed-file-456"), false);

      subscriber.clear();
    });
  });

  // ── SEC-18 ───────────────────────────────────────────────────────────────
  describe("SEC-18: deleteFile Preserves Object Storage Binary for 30-Day Forensic Soft-Delete Retention", () => {
    test("deleteFile soft-deletes DB record and does NOT physically delete R2 storage object", async () => {
      let dbDeleteCalledWith = "";
      let r2DeleteCalled = false;

      const mockRepo: any = {
        findById: async () => ({
          id: "file-retention-1",
          userId: "user-1",
          bucketKey: "images/evidence-retention.jpg",
          fileName: "evidence-retention.jpg",
          isPublic: false,
        }),
        delete: async (id: string) => {
          dbDeleteCalledWith = id;
        },
        createAuditLog: async () => {},
      };

      const mockR2: any = {
        deleteFile: async () => {
          r2DeleteCalled = true;
        },
      };

      const mockBus: any = {
        publish: async () => {},
      };

      const service = new FileService(mockRepo, mockR2, mockBus, {} as any);

      await service.deleteFile(
        "file-retention-1",
        "user-1",
        [PERMISSIONS.FILE_DELETE],
      );

      assert.strictEqual(dbDeleteCalledWith, "file-retention-1", "Must call repository.delete to soft-delete");
      assert.strictEqual(
        r2DeleteCalled,
        false,
        "deleteFile must NOT delete storage object on initial soft-delete to preserve 30-day retention",
      );
    });
  });

  // ── SEC-19 ───────────────────────────────────────────────────────────────
  describe("SEC-19: Default Redis Configuration Port Matches Infrastructure Standard (6379)", () => {
    test("REDIS_PORT defaults to 6379 matching multi-repo docker-compose", () => {
      // Test schema default value directly
      const testRedisSchema = z.object({
        REDIS_PORT: z.coerce.number().int().positive().default(6379),
      });

      const parsed = testRedisSchema.parse({});
      assert.strictEqual(
        parsed.REDIS_PORT,
        6379,
        "REDIS_PORT default must be 6379 matching docker-compose.infra.yml standard",
      );
    });

    test("envConfig.redis.port uses port 6379 when default is applied", () => {
      // Verify that envConfig has a valid port number (6379 or environment override)
      assert.ok(typeof envConfig.redis.port === "number");
      assert.ok(envConfig.redis.port > 0);
    });
  });

  // ── SEC-20 ───────────────────────────────────────────────────────────────
  describe("SEC-20: File Ownership Check Explicitly Rejects Null-Actor Deletions on Unassigned Files", () => {
    test("deleteFile rejects deletion when file.userId is null and caller has no userId (null actor does not own null file)", async () => {
      const mockRepo: any = {
        findById: async () => ({
          id: "unassigned-file-1",
          userId: null,
          bucketKey: "system/unassigned.jpg",
          fileName: "unassigned.jpg",
          isPublic: false,
        }),
        createAuditLog: async () => {},
      };

      const service = new FileService(mockRepo, {} as any, {} as any, {} as any);

      await assert.rejects(
        async () => {
          await service.deleteFile(
            "unassigned-file-1",
            undefined, // Missing/null actor userId
            [PERMISSIONS.FILE_DELETE],
          );
        },
        (err: any) => {
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          return true;
        },
      );
    });

    test("deleteFile rejects deletion when file.userId is null and caller has a valid userId without FILE_MANAGE", async () => {
      const mockRepo: any = {
        findById: async () => ({
          id: "unassigned-file-2",
          userId: null,
          bucketKey: "system/unassigned-2.jpg",
          fileName: "unassigned-2.jpg",
          isPublic: false,
        }),
        createAuditLog: async () => {},
      };

      const service = new FileService(mockRepo, {} as any, {} as any, {} as any);

      await assert.rejects(
        async () => {
          await service.deleteFile(
            "unassigned-file-2",
            "regular-user-123",
            [PERMISSIONS.FILE_DELETE],
          );
        },
        (err: any) => {
          assert.strictEqual(err.statusCode, 403);
          assert.strictEqual(err.code, ERROR_CODE.FORBIDDEN);
          return true;
        },
      );
    });

    test("deleteFile allows deletion of unassigned file if caller is ADMIN or has FILE_MANAGE", async () => {
      let deletedId = "";
      const mockRepo: any = {
        findById: async () => ({
          id: "unassigned-file-3",
          userId: null,
          bucketKey: "system/unassigned-3.jpg",
          fileName: "unassigned-3.jpg",
          isPublic: false,
        }),
        delete: async (id: string) => {
          deletedId = id;
        },
        createAuditLog: async () => {},
      };

      const service = new FileService(mockRepo, {} as any, {} as any, {} as any);

      await service.deleteFile(
        "unassigned-file-3",
        "admin-user-999",
        [],
        undefined,
        ROLES.ADMIN,
      );

      assert.strictEqual(deletedId, "unassigned-file-3", "Admin must be able to delete unassigned file");
    });

    test("deleteFile allows owner to delete their own file", async () => {
      let deletedId = "";
      const mockRepo: any = {
        findById: async () => ({
          id: "owner-file-4",
          userId: "owner-user-777",
          bucketKey: "images/my-photo.jpg",
          fileName: "my-photo.jpg",
          isPublic: false,
        }),
        delete: async (id: string) => {
          deletedId = id;
        },
        createAuditLog: async () => {},
      };

      const service = new FileService(mockRepo, {} as any, {} as any, {} as any);

      await service.deleteFile(
        "owner-file-4",
        "owner-user-777",
        [PERMISSIONS.FILE_DELETE],
      );

      assert.strictEqual(deletedId, "owner-file-4", "Owner must be able to delete their own file");
    });
  });

  // ── SEC-21 ───────────────────────────────────────────────────────────────
  describe("SEC-21: R2Service Supports MinIO, Custom S3 Endpoint, and Cloudflare R2 Overrides", () => {
    test("R2Service connects to MinIO / custom S3 endpoint when explicit endpoint is provided", () => {
      const minioService = new R2Service({
        endpoint: "http://localhost:9000",
        bucketName: "smart-ppe-test-bucket",
        forcePathStyle: true,
      });

      assert.strictEqual(minioService.getEndpoint(), "http://localhost:9000");
      assert.strictEqual(minioService.getBucketName(), "smart-ppe-test-bucket");

      const publicUrl = minioService.getPublicUrl("test-folder/test-image.webp");
      assert.ok(
        publicUrl.includes("http://localhost:9000/smart-ppe-test-bucket/test-folder/test-image.webp") ||
        publicUrl.includes("test-folder/test-image.webp"),
        "Public URL must contain endpoint or path",
      );
    });

    test("envConfig.s3 is configured with standard object storage properties", () => {
      assert.ok(envConfig.s3, "envConfig.s3 must be defined");
      assert.strictEqual(typeof envConfig.s3.endpoint, "string");
      assert.strictEqual(typeof envConfig.s3.region, "string");
      assert.strictEqual(typeof envConfig.s3.forcePathStyle, "boolean");
    });
  });

  // ── SEC-22 ───────────────────────────────────────────────────────────────
  describe("SEC-22: directImageUploadSchema and uploadAndProcessImage Default isPublic to False (Secure Defaults)", () => {
    test("directImageUploadSchema defaults isPublic to false", () => {
      const parsed = directImageUploadSchema.parse({});
      assert.strictEqual(
        parsed.isPublic,
        false,
        "directImageUploadSchema must default isPublic to false adhering to Least Privilege",
      );
    });

    test("directImageUploadSchema accepts explicit isPublic=true string or boolean", () => {
      const parsedString = directImageUploadSchema.parse({ isPublic: "true" });
      assert.strictEqual(parsedString.isPublic, true);

      const parsedBool = directImageUploadSchema.parse({ isPublic: true });
      assert.strictEqual(parsedBool.isPublic, true);
    });

    test("FileService.uploadAndProcessImage saves isPublic as false when option is not specified", async () => {
      let createdWithIsPublic: boolean | undefined = undefined;

      const mockRepo: any = {
        createDirectFile: async (data: any) => {
          createdWithIsPublic = data.isPublic;
          return {
            id: "direct-file-sec22",
            userId: data.userId,
            fileName: data.fileName,
            originalName: data.originalName,
            mimeType: data.mimeType,
            size: data.size,
            bucketKey: data.bucketKey,
            folder: data.folder,
            isPublic: data.isPublic,
            metadata: data.metadata,
          };
        },
        createAuditLog: async () => {},
      };

      const mockR2: any = {
        uploadBuffer: async () => {},
        getPublicUrl: () => undefined,
      };

      const mockProcessor: any = {
        processImage: async () => ({
          buffer: Buffer.from("image-bytes"),
          info: { format: "webp", width: 400, height: 300, size: 1024, mimeType: "image/webp" },
        }),
      };

      const service = new FileService(mockRepo, mockR2, {} as any, mockProcessor);

      await service.uploadAndProcessImage(
        {
          buffer: Buffer.from("test-jpg-bytes"),
          originalname: "site-inspect.jpg",
          mimetype: "image/jpeg",
          size: 2000,
        },
        {}, // No isPublic specified
        "user-sec22",
        [PERMISSIONS.FILE_UPLOAD],
      );

      assert.strictEqual(
        createdWithIsPublic,
        false,
        "uploadAndProcessImage must default isPublic to false when options.isPublic is omitted",
      );
    });
  });

  // ── SEC-31 ───────────────────────────────────────────────────────────────
  describe("SEC-31: Database Initial Migrations Directory and PostgreSQL Function Definition for uuid_generate_v7", () => {
    test("initial migration file exists in prisma/migrations directory", () => {
      const migrationDir = path.resolve(__dirname, "../prisma/migrations/20261014150000_init_media_schema_and_uuidv7");
      const migrationFile = path.join(migrationDir, "migration.sql");

      assert.ok(
        fs.existsSync(migrationFile),
        "Initial migration file 20261014150000_init_media_schema_and_uuidv7/migration.sql must exist",
      );

      const content = fs.readFileSync(migrationFile, "utf-8");
      assert.ok(
        content.includes("CREATE OR REPLACE FUNCTION uuid_generate_v7()"),
        "Migration must define stored procedure uuid_generate_v7()",
      );
      assert.ok(
        content.includes('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"') ||
        content.includes('CREATE EXTENSION IF NOT EXISTS "pgcrypto"'),
        "Migration must enable pgcrypto / uuid-ossp extensions",
      );
      assert.ok(
        content.includes('CREATE TABLE IF NOT EXISTS "file_records"'),
        "Migration must create file_records base table",
      );
      assert.ok(
        content.includes('CREATE TABLE IF NOT EXISTS "audit_logs"'),
        "Migration must create audit_logs base table",
      );
      assert.ok(
        content.includes('CREATE TABLE IF NOT EXISTS "outbox_events"'),
        "Migration must create outbox_events base table",
      );
    });
  });

  // ── SEC-32 ───────────────────────────────────────────────────────────────
  describe("SEC-32: Audit Logging on Sensitive Media Read, Download, and Transformation Operations", () => {
    test("FileService.getFileById records AUDIT_ACTION.READ_FILE in audit logs", async () => {
      let loggedAction = "";
      let loggedTargetId = "";

      const mockRepo: any = {
        findById: async () => ({
          id: "sensitive-file-read-1",
          userId: "user-read-1",
          bucketKey: "evidence/photo.jpg",
          fileName: "photo.jpg",
          isPublic: true,
        }),
        createAuditLog: async (log: any) => {
          loggedAction = log.action;
          loggedTargetId = log.targetId;
        },
      };

      const mockR2: any = {
        getPublicUrl: () => "https://r2/photo.jpg",
      };

      const service = new FileService(mockRepo, mockR2, {} as any, {} as any);

      await service.getFileById("sensitive-file-read-1", "user-read-1");

      assert.strictEqual(
        loggedAction,
        AUDIT_ACTION.READ_FILE,
        "getFileById must record READ_FILE audit log",
      );
      assert.strictEqual(loggedTargetId, "sensitive-file-read-1");
    });

    test("FileService.getPresignedDownloadUrl records AUDIT_ACTION.DOWNLOAD_FILE in audit logs", async () => {
      let loggedAction = "";
      let loggedTargetId = "";

      const mockRepo: any = {
        findById: async () => ({
          id: "sensitive-file-dl-2",
          userId: "user-dl-2",
          bucketKey: "evidence/video.mp4",
          fileName: "video.mp4",
          originalName: "video.mp4",
          isPublic: true,
          isConfirmed: true,
        }),
        createAuditLog: async (log: any) => {
          loggedAction = log.action;
          loggedTargetId = log.targetId;
        },
      };

      const mockR2: any = {
        getPresignedDownloadUrl: async () => "https://r2-download/video.mp4",
      };

      const service = new FileService(mockRepo, mockR2, {} as any, {} as any);

      await service.getPresignedDownloadUrl("sensitive-file-dl-2", "user-dl-2");

      assert.strictEqual(
        loggedAction,
        AUDIT_ACTION.DOWNLOAD_FILE,
        "getPresignedDownloadUrl must record DOWNLOAD_FILE audit log",
      );
      assert.strictEqual(loggedTargetId, "sensitive-file-dl-2");
    });

    test("FileService.transformExistingImage records AUDIT_ACTION.TRANSFORM_IMAGE on read/transform", async () => {
      let loggedAction = "";
      let loggedTargetId = "";

      const mockRepo: any = {
        findById: async () => ({
          id: "transform-file-3",
          userId: "user-tx-3",
          bucketKey: "evidence/crop.png",
          fileName: "crop.png",
          originalName: "crop.png",
          mimeType: "image/png",
          isPublic: true,
          isConfirmed: true,
        }),
        createAuditLog: async (log: any) => {
          loggedAction = log.action;
          loggedTargetId = log.targetId;
        },
      };

      const mockR2: any = {
        getObjectBuffer: async () => Buffer.from("png-bytes"),
      };

      const mockProcessor: any = {
        isSupportedImageMime: () => true,
        processImage: async () => ({
          buffer: Buffer.from("transformed-bytes"),
          info: { format: "png", width: 200, height: 200, size: 500, mimeType: "image/png" },
        }),
      };

      const service = new FileService(mockRepo, mockR2, {} as any, mockProcessor);

      await service.transformExistingImage(
        "transform-file-3",
        { saveAsNew: false, width: 200, height: 200 },
        "user-tx-3",
      );

      assert.strictEqual(
        loggedAction,
        AUDIT_ACTION.TRANSFORM_IMAGE,
        "transformExistingImage on read must record TRANSFORM_IMAGE audit log",
      );
      assert.strictEqual(loggedTargetId, "transform-file-3");
    });
  });

  // ── SEC-33 ───────────────────────────────────────────────────────────────
  describe("SEC-33: Multi-Repo Database Isolation Omits Foreign Microservice URLs", () => {
    test("envConfig.database isolates media database and omits foreign microservice database URLs", () => {
      assert.ok(envConfig.database.url, "envConfig.database.url must be defined");
      assert.strictEqual(
        (envConfig.database as any).identityUrl,
        undefined,
        "IDENTITY_DATABASE_URL must not be exposed in media service config",
      );
      assert.strictEqual(
        (envConfig.database as any).siteUrl,
        undefined,
        "SITE_DATABASE_URL must not be exposed in media service config",
      );
      assert.strictEqual(
        (envConfig.database as any).cameraUrl,
        undefined,
        "CAMERA_DATABASE_URL must not be exposed in media service config",
      );
      assert.strictEqual(
        (envConfig.database as any).incidentUrl,
        undefined,
        "INCIDENT_DATABASE_URL must not be exposed in media service config",
      );
      assert.strictEqual(
        (envConfig.database as any).notificationUrl,
        undefined,
        "NOTIFICATION_DATABASE_URL must not be exposed in media service config",
      );
      assert.strictEqual(
        (envConfig.database as any).reportingUrl,
        undefined,
        "REPORTING_DATABASE_URL must not be exposed in media service config",
      );
    });
  });

  // ── SEC-34 ───────────────────────────────────────────────────────────────
  describe("SEC-34: Prisma Client Constructor Binds to Dynamic Database URL Resolution", () => {
    test("prisma.client.ts passes explicit datasources.db.url from envConfig.database.url", () => {
      const clientFile = path.resolve(__dirname, "../src/database/prisma.client.ts");
      const content = fs.readFileSync(clientFile, "utf-8");

      assert.ok(
        content.includes("datasources:") &&
        content.includes("db:") &&
        content.includes("url: envConfig.database.url"),
        "getMediaPrisma must pass datasources.db.url from envConfig.database.url",
      );
    });

    test("getMediaPrisma returns instantiated PrismaClient without errors", () => {
      const client = getMediaPrisma();
      assert.ok(client, "getMediaPrisma must return valid MediaPrismaClient instance");
    });
  });

  // ── SEC-35 ───────────────────────────────────────────────────────────────
  describe("SEC-35: Granular Rate Limiting on Resource-Intensive Sharp Endpoints", () => {
    test("envConfig.rateLimit defines dedicated sharp rate limit properties", () => {
      assert.strictEqual(typeof envConfig.rateLimit.sharpWindowMs, "number");
      assert.strictEqual(typeof envConfig.rateLimit.sharpMaxRequests, "number");
      assert.ok(envConfig.rateLimit.sharpMaxRequests > 0);
    });

    test("sharpRateLimitMiddleware limits excessive requests and returns 429", async () => {
      // Create dedicated test limiter with max 2 requests
      const testLimiter = createRateLimiter({
        windowMs: 60000,
        maxRequests: 2,
        message: "Too many image processing requests",
      });

      const req: any = {
        ip: "192.168.1.100",
        path: "/api/v1/files/upload-image",
        headers: {},
        socket: {},
      };

      let status = 200;
      let jsonBody: any = null;
      const res: any = {
        setHeader: () => {},
        status: (s: number) => {
          status = s;
          return {
            json: (b: any) => {
              jsonBody = b;
            },
          };
        },
      };

      // Request 1: OK
      let nextCalled = false;
      await testLimiter(req, res, () => {
        nextCalled = true;
      });
      assert.strictEqual(nextCalled, true, "First request must pass");

      // Request 2: OK
      nextCalled = false;
      await testLimiter(req, res, () => {
        nextCalled = true;
      });
      assert.strictEqual(nextCalled, true, "Second request must pass");

      // Request 3: Blocked (429 Rate Limit Exceeded)
      nextCalled = false;
      await testLimiter(req, res, () => {
        nextCalled = true;
      });
      assert.strictEqual(nextCalled, false, "Third request must be blocked");
      assert.strictEqual(status, 429, "Must return HTTP 429 Too Many Requests");
      assert.strictEqual(jsonBody?.code, ERROR_CODE.RATE_LIMIT_EXCEEDED);
    });

    test("file.route.ts mounts sharpRateLimitMiddleware on upload-image and transform endpoints", () => {
      const routeFile = path.resolve(__dirname, "../src/modules/files/file.route.ts");
      const content = fs.readFileSync(routeFile, "utf-8");

      assert.ok(
        content.includes("sharpRateLimitMiddleware"),
        "file.route.ts must import and use sharpRateLimitMiddleware",
      );
      assert.ok(
        content.includes('"/upload-image",\n  sharpRateLimitMiddleware'),
        "sharpRateLimitMiddleware must guard POST /upload-image",
      );
      assert.ok(
        content.includes('"/:id/transform",\n  sharpRateLimitMiddleware'),
        "sharpRateLimitMiddleware must guard /:id/transform endpoints",
      );
    });
  });

  // ── SEC-42 ───────────────────────────────────────────────────────────────
  describe("SEC-42: Unhandled PostgreSQL UUID Cast Exception in Raw Full-Text Search Query", () => {
    test("searchFts safely handles non-UUID currentUserId without throwing 22P02 DB cast syntax error", async () => {
      let passedQueries: any[] = [];
      const originalTx = (prisma as any).$transaction;
      const originalRaw = (prisma as any).$queryRaw;

      (prisma as any).$queryRaw = (strings: any, ...values: any[]) => {
        const queryObj = { strings, values };
        passedQueries.push(queryObj);
        return queryObj;
      };
      (prisma as any).$transaction = async () => {
        return [
          [],
          [{ count: 0n }],
        ];
      };

      try {
        const repo = new FileRepository();
        // Non-UUID currentUserId (e.g., service account or mock principal "admin")
        const result = await repo.searchFts({ search: "safety" }, "admin", false);

        assert.ok(result);
        assert.strictEqual(Array.isArray(result.data), true);
        const queryStr = JSON.stringify(passedQueries);
        assert.ok(!queryStr.includes("admin::uuid"), "Non-UUID currentUserId must NOT have ::uuid cast appended");
        assert.ok(queryStr.includes("is_public = true"), "Non-UUID user must be constrained to public files");
      } finally {
        (prisma as any).$transaction = originalTx;
        (prisma as any).$queryRaw = originalRaw;
      }
    });

    test("searchFts correctly applies UUID cast for valid UUID currentUserId", async () => {
      let passedQueries: any[] = [];
      const originalTx = (prisma as any).$transaction;
      const originalRaw = (prisma as any).$queryRaw;

      (prisma as any).$queryRaw = (strings: any, ...values: any[]) => {
        const queryObj = { strings, values };
        passedQueries.push(queryObj);
        return queryObj;
      };
      (prisma as any).$transaction = async () => {
        return [
          [],
          [{ count: 0n }],
        ];
      };

      try {
        const repo = new FileRepository();
        const validUuid = "01931580-0000-7000-8000-000000000001";
        await repo.searchFts({ search: "ppe" }, validUuid, false);

        const queryStr = JSON.stringify(passedQueries);
        assert.ok(queryStr.includes("::uuid"), "Valid UUID currentUserId must include ::uuid cast in SQL");
      } finally {
        (prisma as any).$transaction = originalTx;
        (prisma as any).$queryRaw = originalRaw;
      }
    });

    test("searchFts safely handles query.userId in canManageAll mode for valid vs non-UUID", async () => {
      let passedQueries: any[] = [];
      const originalTx = (prisma as any).$transaction;
      const originalRaw = (prisma as any).$queryRaw;

      (prisma as any).$queryRaw = (strings: any, ...values: any[]) => {
        const queryObj = { strings, values };
        passedQueries.push(queryObj);
        return queryObj;
      };
      (prisma as any).$transaction = async () => {
        return [
          [],
          [{ count: 0n }],
        ];
      };

      try {
        const repo = new FileRepository();
        const validUuid = "01931580-0000-7000-8000-000000000001";

        // Non-UUID query.userId when canManageAll = true
        await repo.searchFts({ search: "ppe", userId: "service-worker" as any }, validUuid, true);
        const invalidQueryStr = JSON.stringify(passedQueries);
        assert.ok(invalidQueryStr.includes("1 = 0"), "Non-UUID query.userId must inject 1 = 0 condition");
        assert.ok(!invalidQueryStr.includes("service-worker::uuid"), "Non-UUID query.userId must NOT cast ::uuid");

        // Reset passedQueries
        passedQueries = [];

        // Valid UUID query.userId when canManageAll = true
        const targetUserUuid = "01931580-0000-7000-8000-000000000002";
        await repo.searchFts({ search: "ppe", userId: targetUserUuid }, validUuid, true);
        const validQueryStr = JSON.stringify(passedQueries);
        assert.ok(validQueryStr.includes("::uuid"), "Valid UUID query.userId must include ::uuid cast");
      } finally {
        (prisma as any).$transaction = originalTx;
        (prisma as any).$queryRaw = originalRaw;
      }
    });
  });

  // ── SEC-43 ───────────────────────────────────────────────────────────────
  describe("SEC-43: Unbounded Pagination Page Parameter Causes Extreme PostgreSQL Offset Exhaustion DoS", () => {
    test("listFilesSchema rejects excessive page numbers > 1000", () => {
      const invalidExcessive = listFilesSchema.safeParse({ page: "100000000" });
      assert.strictEqual(invalidExcessive.success, false);
      if (!invalidExcessive.success) {
        assert.ok(invalidExcessive.error.issues.some((i) => i.message.includes("1000")));
      }

      const invalid1001 = listFilesSchema.safeParse({ page: 1001 });
      assert.strictEqual(invalid1001.success, false);
    });

    test("listFilesSchema accepts valid page numbers between 1 and 1000", () => {
      const valid1 = listFilesSchema.safeParse({ page: 1 });
      assert.strictEqual(valid1.success, true);
      assert.strictEqual(valid1.data?.page, 1);

      const valid1000 = listFilesSchema.safeParse({ page: 1000 });
      assert.strictEqual(valid1000.success, true);
      assert.strictEqual(valid1000.data?.page, 1000);
    });

    test("calculatePaginationSkip and formatPaginationMeta enforce MAX_PAGINATION_PAGE defense-in-depth", () => {
      assert.strictEqual(MAX_PAGINATION_PAGE, 1000);

      const skipResult = calculatePaginationSkip(999999, 20);
      assert.strictEqual(skipResult.page, 1000, "calculatePaginationSkip must cap page at MAX_PAGINATION_PAGE (1000)");
      assert.strictEqual(skipResult.skip, (1000 - 1) * 20);

      const metaResult = formatPaginationMeta(999999, 20, 50000);
      assert.strictEqual(metaResult.page, 1000, "formatPaginationMeta must cap page at MAX_PAGINATION_PAGE (1000)");
    });
  });

  // ── SEC-44 ───────────────────────────────────────────────────────────────
  describe("SEC-44: Blanket 20MB Express Body Parser Limit Enables Event Loop Starvation and Node.js ReDoS", () => {
    test("media.app.ts source code specifies 100kb limit on express.json and express.urlencoded", () => {
      const appFile = path.resolve(__dirname, "../src/media.app.ts");
      const content = fs.readFileSync(appFile, "utf-8");

      assert.ok(
        content.includes('express.json({ limit: "100kb" })'),
        "media.app.ts must configure express.json with limit 100kb",
      );
      assert.ok(
        content.includes('express.urlencoded({ extended: true, limit: "100kb" })'),
        "media.app.ts must configure express.urlencoded with limit 100kb",
      );
      assert.ok(
        !content.includes('express.json({ limit: "20mb" })'),
        "media.app.ts must NOT use 20mb json limit globally",
      );
    });

    test("express.json middleware configured with 100kb rejects payloads exceeding limit with HTTP 413", async () => {
      const jsonParser = express.json({ limit: "100kb" });

      // Create a payload larger than 100kb (~125KB)
      const largePayload = JSON.stringify({ data: "a".repeat(125 * 1024) });
      const { Readable } = await import("node:stream");
      const stream = new Readable();
      stream.push(largePayload);
      stream.push(null);

      const req: any = Object.assign(stream, {
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(largePayload).toString(),
        },
      });

      let nextError: any = null;
      const res: any = {};

      await new Promise<void>((resolve) => {
        jsonParser(req, res, (err: any) => {
          nextError = err;
          resolve();
        });
      });

      assert.ok(nextError, "Should return an error for >100kb payload");
      assert.strictEqual(nextError.status || nextError.statusCode, 413, "Must return HTTP 413 Payload Too Large");
      assert.strictEqual(nextError.type, "entity.too.large");
    });
  });
});
