import { test, describe, before } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import { authMiddleware } from "../src/middlewares/auth.middleware";
import { requirePermission, requireAnyPermission } from "../src/middlewares/permission.middleware";
import { FileController } from "../src/modules/files/file.controller";
import { jwtKeyService } from "../src/common/services/jwt-key.service";
import { JWT_PURPOSE, JWT_ALGORITHM } from "../src/common/constants/jwt.constant";
import { ROLES } from "../src/common/constants/role.constant";
import { PERMISSIONS } from "../src/common/constants/permission.constant";
import { AppError } from "../src/common/errors/app-error";

describe("P0 Security Vulnerabilities Patch Verification (SEC-01 - SEC-04)", () => {
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
});
