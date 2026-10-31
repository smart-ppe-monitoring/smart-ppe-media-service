import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import jwt from "jsonwebtoken";
import { authMiddleware } from "../src/middlewares/auth.middleware";
import { requirePermission, requireAnyPermission } from "../src/middlewares/permission.middleware";
import { FileController } from "../src/modules/files/file.controller";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { JWT_PURPOSE, JWT_ALGORITHM } from "../src/common/constants/jwt.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { AppError } from "../src/common/errors/app-error";
import { ERROR_CODE } from "../src/common/errors/error-code";
import {
  imageTransformQuerySchema,
  imageTransformBodySchema,
  requestUploadUrlSchema,
} from "../src/modules/files/file.validation";
import { DEFAULT_ALLOWED_MIME_TYPES } from "../src/common/constants/system-config.constant";
import { FileService } from "../src/modules/files/file.service";
import { uploadImageMiddleware } from "../src/middlewares/upload.middleware";
import {
  createVerifyJwtLocally,
  clearJwtPublicKeyCache,
} from "../src/middlewares/verify-jwt-locally.middleware";
import { JwtKeyService } from "../src/common/services/jwt-key.service";
import { envConfig } from "../src/config/env.config";
import { jwtConfig } from "../src/config/jwt.config";

describe("P0 Security Vulnerabilities Patch Verification (SEC-01 - SEC-04, SEC-23 - SEC-24, SEC-36 - SEC-37)", () => {
  let rsaPrivateKey: string;
  let rsaPublicKey: string;

  before(() => {
    // Generate valid RSA keypair for testing
    const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    rsaPrivateKey = privateKey;
    rsaPublicKey = publicKey;

    // Inject into key service
    (jwtKeyService as any).publicKeyPem = rsaPublicKey;
    (jwtKeyService as any).privateKeyPem = rsaPrivateKey;
  });

  describe("SEC-01: Disallow HS256 algorithm confusion", () => {
    test("rejects token signed with HS256 using public key as secret", async () => {
      // Attacker attempts HMAC-SHA256 signature using the public key as symmetric secret
      const forgedToken = jwt.sign(
        { id: "attacker-user-id", role: "ADMIN", purpose: "ACCESS" },
        rsaPublicKey,
        { algorithm: "HS256" },
      );

      const req: any = {
        headers: { authorization: `Bearer ${forgedToken}` },
        query: {},
      };
      const res: any = {};
      let caughtError: any = null;

      await authMiddleware(req, res, (err: any) => {
        caughtError = err;
      });

      assert.ok(caughtError instanceof AppError, "Should reject with AppError");
      assert.strictEqual(caughtError.statusCode, 401);
      assert.strictEqual(req.user, undefined, "req.user must not be set");
    });

    test("accepts valid token signed with RS256", async () => {
      const validToken = jwt.sign(
        { id: "legit-user-id", email: "user@test.local", role: "USER", purpose: "ACCESS" },
        rsaPrivateKey,
        { algorithm: "RS256" },
      );

      const req: any = {
        headers: { authorization: `Bearer ${validToken}` },
        query: {},
      };
      const res: any = {};
      let nextCalled = false;

      await authMiddleware(req, res, (err: any) => {
        assert.ifError(err);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true);
      assert.ok(req.user);
      assert.strictEqual(req.user.id, "legit-user-id");
    });
  });

  describe("SEC-02: Prevent temporary 2FA tokens from accessing protected media API", () => {
    test("rejects token with purpose '2FA_VERIFICATION'", async () => {
      const twoFactorToken = jwt.sign(
        { id: "user-with-2fa", role: "ADMIN", purpose: JWT_PURPOSE.TWO_FACTOR },
        rsaPrivateKey,
        { algorithm: "RS256" },
      );

      const req: any = {
        headers: { authorization: `Bearer ${twoFactorToken}` },
        query: {},
      };
      const res: any = {};
      let caughtError: any = null;

      await authMiddleware(req, res, (err: any) => {
        caughtError = err;
      });

      assert.ok(caughtError instanceof AppError);
      assert.strictEqual(caughtError.statusCode, 401);
      assert.match(caughtError.message, /Token không hợp lệ để truy cập tài nguyên được bảo vệ/);
      assert.strictEqual(req.user, undefined);
    });

    test("rejects token with type 'TEMP'", async () => {
      const tempToken = jwt.sign(
        { id: "temp-user", role: "ADMIN", type: "TEMP" },
        rsaPrivateKey,
        { algorithm: "RS256" },
      );

      const req: any = {
        headers: { authorization: `Bearer ${tempToken}` },
        query: {},
      };
      const res: any = {};
      let caughtError: any = null;

      await authMiddleware(req, res, (err: any) => {
        caughtError = err;
      });

      assert.ok(caughtError instanceof AppError);
      assert.strictEqual(caughtError.statusCode, 401);
    });
  });

  describe("SEC-03: Scope API Key permissions and prevent Admin bypass", () => {
    test("human Admin user without API key can bypass permission checks", () => {
      const middleware = requirePermission(PERMISSIONS.FILE_MANAGE);
      const req: any = {
        user: { id: "admin-1", role: ROLES.ADMIN, permissions: [] },
      };
      const res: any = {};
      let nextCalled = false;

      middleware(req, res, (err: any) => {
        assert.ifError(err);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true, "Admin session should bypass permission check");
    });

    test("Admin request via API Key with restricted permissions is blocked if permission missing", () => {
      const middleware = requirePermission(PERMISSIONS.FILE_MANAGE);
      const req: any = {
        user: { id: "admin-1", role: ROLES.ADMIN, permissions: [] },
        apiKey: {
          id: "key-1",
          name: "Read-only Key",
          prefix: "sk_read",
          permissions: [PERMISSIONS.FILE_READ], // No FILE_MANAGE permission
        },
      };
      const res: any = {};
      let caughtError: any = null;

      middleware(req, res, (err: any) => {
        caughtError = err;
      });

      assert.ok(caughtError instanceof AppError, "Should return 403 Forbidden");
      assert.strictEqual(caughtError.statusCode, 403);
    });

    test("Admin request via API Key with required permission is allowed", () => {
      const middleware = requireAnyPermission(PERMISSIONS.FILE_READ, PERMISSIONS.FILE_MANAGE);
      const req: any = {
        user: { id: "admin-1", role: ROLES.ADMIN, permissions: [] },
        apiKey: {
          id: "key-2",
          name: "Media Read Key",
          prefix: "sk_read",
          permissions: [PERMISSIONS.FILE_READ],
        },
      };
      const res: any = {};
      let nextCalled = false;

      middleware(req, res, (err: any) => {
        assert.ifError(err);
        nextCalled = true;
      });

      assert.strictEqual(nextCalled, true, "API key with matching permission must be allowed");
    });
  });

  describe("SEC-04: Enforce Cache-Control: private for sensitive / private media", () => {
    test("sets Cache-Control: private for private media buffer", async () => {
      const mockService: any = {
        transformExistingImage: async () => ({
          buffer: Buffer.from("mock-binary-image"),
          info: { format: "jpeg", size: 17, mimeType: "image/jpeg" },
          isPublic: false,
        }),
      };

      const controller = new FileController(mockService);
      const req: any = {
        params: { id: "018f-private-file" },
        query: {},
        user: { id: "user-1", permissions: [] },
      };

      const headers: Record<string, string> = {};
      let responseBody: any = null;
      const res: any = {
        setHeader: (key: string, value: string) => {
          headers[key] = value;
        },
        send: (body: any) => {
          responseBody = body;
        },
      };

      await controller.transformImage(req, res, () => {});

      assert.strictEqual(headers["Cache-Control"], "private, no-cache, no-store, must-revalidate");
      assert.strictEqual(headers["Pragma"], "no-cache");
      assert.strictEqual(headers["Expires"], "0");
      assert.ok(Buffer.isBuffer(responseBody));
    });

    test("sets Cache-Control: public for public media buffer", async () => {
      const mockService: any = {
        transformExistingImage: async () => ({
          buffer: Buffer.from("mock-binary-image"),
          info: { format: "png", size: 17, mimeType: "image/png" },
          isPublic: true,
        }),
      };

      const controller = new FileController(mockService);
      const req: any = {
        params: { id: "018f-public-file" },
        query: {},
        user: { id: "user-1", permissions: [] },
      };

      const headers: Record<string, string> = {};
      const res: any = {
        setHeader: (key: string, value: string) => {
          headers[key] = value;
        },
        send: () => {},
      };

      await controller.transformImage(req, res, () => {});

      assert.strictEqual(headers["Cache-Control"], "public, max-age=86400, stale-while-revalidate=3600");
    });
  });

  describe("SEC-23: Disallow state mutation and CSRF file creation via HTTP GET", () => {
    test("imageTransformQuerySchema rejects saveAsNew=true", () => {
      const result = imageTransformQuerySchema.safeParse({
        width: 300,
        height: 200,
        saveAsNew: "true",
      });
      assert.strictEqual(result.success, false);
      if (!result.success) {
        const errorMessages = result.error.errors.map((e) => e.message);
        assert.ok(
          errorMessages.some((msg) =>
            msg.includes("Không được phép lưu biến thể tệp mới qua HTTP GET"),
          ),
          "Must reject saveAsNew on GET schema",
        );
      }
    });

    test("imageTransformQuerySchema allows valid transform options and saveAsNew=false", () => {
      const result = imageTransformQuerySchema.safeParse({
        width: 300,
        height: 200,
        format: "webp",
        saveAsNew: false,
      });
      assert.strictEqual(result.success, true);
      if (result.success) {
        assert.strictEqual(result.data.saveAsNew, false);
        assert.strictEqual(result.data.width, 300);
      }
    });

    test("imageTransformBodySchema allows saveAsNew=true for POST requests", () => {
      const result = imageTransformBodySchema.safeParse({
        width: 400,
        height: 300,
        format: "jpeg",
        saveAsNew: true,
      });
      assert.strictEqual(result.success, true);
      if (result.success) {
        assert.strictEqual(result.data.saveAsNew, true);
        assert.strictEqual(result.data.width, 400);
      }
    });

    test("FileController.transformImage forces saveAsNew=false on HTTP GET even if query attempts it", async () => {
      let passedOptions: any = null;
      const mockService: any = {
        transformExistingImage: async (_id: string, options: any) => {
          passedOptions = options;
          return {
            buffer: Buffer.from("transformed-binary"),
            info: { format: "webp", size: 18, mimeType: "image/webp" },
            isPublic: true,
          };
        },
      };

      const controller = new FileController(mockService);
      const req: any = {
        method: "GET",
        params: { id: "018f-image-id" },
        query: { width: 300, saveAsNew: true },
        user: { id: "user-1", permissions: [] },
      };

      const res: any = {
        setHeader: () => {},
        send: () => {},
      };

      await controller.transformImage(req, res, () => {});

      assert.ok(passedOptions);
      assert.strictEqual(passedOptions.saveAsNew, false, "GET must force saveAsNew to false");
    });

    test("FileController.transformImage allows saveAsNew=true on HTTP POST and returns 201 Created", async () => {
      let passedOptions: any = null;
      const createdRecord = {
        id: "new-transformed-record-uuid",
        fileName: "transformed_abc.webp",
        bucketKey: "images/user-1/transformed_abc.webp",
        isPublic: true,
      };

      const mockService: any = {
        transformExistingImage: async (_id: string, options: any) => {
          passedOptions = options;
          return createdRecord;
        },
      };

      const controller = new FileController(mockService);
      const req: any = {
        method: "POST",
        params: { id: "018f-image-id" },
        body: { width: 300, format: "webp", saveAsNew: true },
        user: { id: "user-1", permissions: [PERMISSIONS.FILE_UPLOAD] },
      };

      let statusCode = 200;
      let jsonResponse: any = null;
      const res: any = {
        status: (code: number) => {
          statusCode = code;
          return res;
        },
        json: (data: any) => {
          jsonResponse = data;
        },
      };

      await controller.transformImage(req, res, () => {});

      assert.ok(passedOptions);
      assert.strictEqual(passedOptions.saveAsNew, true, "POST must allow saveAsNew=true");
      assert.strictEqual(statusCode, 201, "POST must return 201 Created status");
      assert.strictEqual(jsonResponse.success, true);
      assert.strictEqual(jsonResponse.data.id, "new-transformed-record-uuid");
    });
  });

  describe("SEC-24: Prevent SVG upload leading to Stored XSS", () => {
    test("DEFAULT_ALLOWED_MIME_TYPES excludes 'image/*' wildcard and SVG formats", () => {
      const allowedList = DEFAULT_ALLOWED_MIME_TYPES as readonly string[];
      assert.strictEqual(allowedList.includes("image/*"), false, "Wildcard image/* must not be present");
      assert.strictEqual(allowedList.includes("image/svg+xml"), false, "image/svg+xml must not be in default allowed");
      assert.strictEqual(allowedList.includes("image/svg"), false, "image/svg must not be in default allowed");
    });

    test("FileService.isMimeTypeAllowed blocks SVG variants even if wildcard image/* were configured", () => {
      const service = new FileService({} as any, {} as any, {} as any, {} as any);
      const isAllowed = (service as any).isMimeTypeAllowed.bind(service);

      // SVG variants
      assert.strictEqual(isAllowed("image/svg+xml", ["image/*"]), false);
      assert.strictEqual(isAllowed("IMAGE/SVG+XML", ["image/*"]), false);
      assert.strictEqual(isAllowed("image/svg", ["image/*"]), false);
      assert.strictEqual(isAllowed("image/vnd.adobe.svg+xml", ["image/*"]), false);
      assert.strictEqual(isAllowed("text/xml-svg", ["*/*"]), false);

      // Safe images
      assert.strictEqual(isAllowed("image/jpeg", ["image/*"]), true);
      assert.strictEqual(isAllowed("image/png", ["image/*"]), true);
      assert.strictEqual(isAllowed("image/webp", ["image/*"]), true);
    });

    test("requestUploadUrlSchema rejects SVG fileName and SVG mimeType", () => {
      // Reject .svg extension
      const extCheck = requestUploadUrlSchema.safeParse({
        fileName: "malicious-vector.svg",
        mimeType: "image/png",
      });
      assert.strictEqual(extCheck.success, false);

      // Reject .svgz extension
      const svgzCheck = requestUploadUrlSchema.safeParse({
        fileName: "malicious-vector.svgz",
        mimeType: "image/png",
      });
      assert.strictEqual(svgzCheck.success, false);

      // Reject image/svg+xml mimeType
      const mimeCheck = requestUploadUrlSchema.safeParse({
        fileName: "safe-looking-name.png",
        mimeType: "image/svg+xml",
      });
      assert.strictEqual(mimeCheck.success, false);

      // Accept legitimate file
      const validCheck = requestUploadUrlSchema.safeParse({
        fileName: "profile.png",
        mimeType: "image/png",
      });
      assert.strictEqual(validCheck.success, true);
    });

    test("FileService.requestUploadUrl throws AppError for SVG file", async () => {
      const service = new FileService({} as any, {} as any, {} as any, {} as any);

      await assert.rejects(
        async () => {
          await service.requestUploadUrl({
            fileName: "xss-payload.svg",
            mimeType: "image/svg+xml",
            size: 1024,
            isPublic: true,
          });
        },
        (err: any) => {
          assert.ok(err instanceof AppError);
          assert.strictEqual(err.statusCode, 400);
          assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
          return true;
        },
      );
    });

    test("uploadImageMiddleware rejects files with .svg extension", (_t, done) => {
      const fileFilter = (uploadImageMiddleware as any).fileFilter;
      const mockFile = {
        mimetype: "image/png", // Disguised mime type
        originalname: "payload.svg",
      };

      fileFilter(null, mockFile, (err: any, accepted?: boolean) => {
        assert.ok(err instanceof AppError, "Should reject with AppError");
        assert.strictEqual(err.statusCode, 400);
        assert.strictEqual(err.code, ERROR_CODE.VALIDATION_ERROR);
        assert.strictEqual(accepted, undefined);
        done();
      });
    });
  });

  describe("SEC-36: Mitigate JWKS fetch key rotation unbounded HTTP amplification DoS", () => {
    const originalFetch = globalThis.fetch;

    test("coalesces concurrent requests for unknown kid into a single outbound fetch", async () => {
      let fetchCount = 0;
      globalThis.fetch = (async () => {
        fetchCount++;
        await new Promise((resolve) => setTimeout(resolve, 30));
        return {
          ok: true,
          json: async () => ({
            keys: [
              {
                kty: "RSA",
                kid: "identity-key-alpha",
                use: "sig",
                alg: "RS256",
                n: "u123",
                e: "AQAB",
              },
            ],
          }),
        } as any;
      }) as any;

      clearJwtPublicKeyCache();

      const middleware = createVerifyJwtLocally({
        jwksUri: "https://auth-service.local/.well-known/jwks.json",
        autoRefreshOnUnknownKid: true,
      });

      // Dispatch 5 concurrent requests with tokens having unknown kid
      const requests = Array.from({ length: 5 }).map(async (_, idx) => {
        const token = jwt.sign(
          { id: `user-${idx}`, role: "USER", purpose: "ACCESS" },
          rsaPrivateKey,
          { algorithm: "RS256", keyid: "unknown-kid-concurrent" },
        );
        const req: any = {
          headers: { authorization: `Bearer ${token}` },
        };
        const res: any = {};
        let errResult: any = null;
        await middleware(req, res, (err) => {
          errResult = err;
        });
        return errResult;
      });

      const results = await Promise.all(requests);

      // Verify all requests received an error (kid was not in JWKS)
      for (const err of results) {
        assert.ok(err instanceof AppError);
      }

      // Assert that exactly 1 outbound HTTP call was made (single-flight coalesced)
      assert.strictEqual(fetchCount, 1, "Must coalesce concurrent JWKS requests into 1 fetch");
    });

    test("enforces cooldown to block rapid consecutive outbound JWKS fetches", async () => {
      let fetchCount = 0;
      globalThis.fetch = (async () => {
        fetchCount++;
        return {
          ok: true,
          json: async () => ({
            keys: [],
          }),
        } as any;
      }) as any;

      clearJwtPublicKeyCache();

      const middleware = createVerifyJwtLocally({
        jwksUri: "https://auth-service.local/.well-known/jwks.json",
        autoRefreshOnUnknownKid: true,
      });

      // First call triggers fetch
      const token1 = jwt.sign(
        { id: "user-1", role: "USER", purpose: "ACCESS" },
        rsaPrivateKey,
        { algorithm: "RS256", keyid: "kid-cooldown-1" },
      );
      await middleware({ headers: { authorization: `Bearer ${token1}` } } as any, {} as any, () => {});
      assert.strictEqual(fetchCount, 1, "First request must trigger fetch");

      // Immediate second request with a different kid within 10s cooldown
      const token2 = jwt.sign(
        { id: "user-2", role: "USER", purpose: "ACCESS" },
        rsaPrivateKey,
        { algorithm: "RS256", keyid: "kid-cooldown-2" },
      );
      await middleware({ headers: { authorization: `Bearer ${token2}` } } as any, {} as any, () => {});

      // Fetch count should NOT increase due to 10s cooldown
      assert.strictEqual(fetchCount, 1, "Consecutive request within cooldown must not fire second outbound fetch");
    });

    test("negative cache (tombstone) rejects repeated lookups for same invalid kid without fetch", async () => {
      let fetchCount = 0;
      globalThis.fetch = (async () => {
        fetchCount++;
        return {
          ok: true,
          json: async () => ({ keys: [] }),
        } as any;
      }) as any;

      clearJwtPublicKeyCache();

      const middleware = createVerifyJwtLocally({
        jwksUri: "https://auth-service.local/.well-known/jwks.json",
      });

      const token = jwt.sign(
        { id: "user-1", role: "USER", purpose: "ACCESS" },
        rsaPrivateKey,
        { algorithm: "RS256", keyid: "bogus-tombstoned-kid" },
      );

      // First request
      await middleware({ headers: { authorization: `Bearer ${token}` } } as any, {} as any, () => {});
      const initialFetchCount = fetchCount;

      // Second request with same bogus kid
      await middleware({ headers: { authorization: `Bearer ${token}` } } as any, {} as any, () => {});

      assert.strictEqual(fetchCount, initialFetchCount, "Tombstoned kid must not re-trigger fetch");

      // Restore fetch
      globalThis.fetch = originalFetch;
    });
  });

  describe("SEC-37: JwtKeyService fails fast and preserves trusted Public Key in decentralized auth", () => {
    test("preserves configured Public Key when Private Key is absent on satellite service", () => {
      const origPublic = jwtConfig.publicKey;
      const origPrivate = jwtConfig.privateKey;

      try {
        // Satellite service has only Public Key
        (jwtConfig as any).publicKey = rsaPublicKey;
        (jwtConfig as any).privateKey = "";

        const service = new JwtKeyService();
        assert.strictEqual(service.getPublicKeyPem().trim(), rsaPublicKey.trim());
        assert.strictEqual(service.getPrivateKeyPem(), "");
      } finally {
        (jwtConfig as any).publicKey = origPublic;
        (jwtConfig as any).privateKey = origPrivate;
      }
    });

    test("fails fast in production when trusted Public Key is missing", () => {
      const origPublic = jwtConfig.publicKey;
      const origPrivate = jwtConfig.privateKey;
      const origNodeEnv = envConfig.nodeEnv;
      const origExistsSync = fs.existsSync;

      try {
        (jwtConfig as any).publicKey = "";
        (jwtConfig as any).privateKey = "";
        (envConfig as any).nodeEnv = "production";
        // Giả lập keys không tồn tại trên ổ đĩa
        (fs as any).existsSync = () => false;

        assert.throws(
          () => {
            new JwtKeyService();
          },
          (err: any) => {
            assert.ok(err instanceof Error);
            assert.ok(
              err.message.includes("FATAL: Trusted JWT Public Key not found"),
              `Expected fatal error message, got: ${err.message}`,
            );
            return true;
          },
        );
      } finally {
        (jwtConfig as any).publicKey = origPublic;
        (jwtConfig as any).privateKey = origPrivate;
        (envConfig as any).nodeEnv = origNodeEnv;
        (fs as any).existsSync = origExistsSync;
      }
    });
  });
});
