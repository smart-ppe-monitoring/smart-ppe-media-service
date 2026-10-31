import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import cookieParser from "cookie-parser";
import {
  errorMiddleware,
  notFoundMiddleware,
} from "./middlewares/error.middleware";
import fileRoute from "./modules/files/file.route";
import { rateLimitMiddleware } from "./middlewares/rate-limit.middleware";
import {
  requestIdMiddleware,
  requireGatewayOrigin,
} from "./middlewares/request-id.middleware";
import { maintenanceGuard } from "./middlewares/maintenance.middleware";
import { envConfig } from "./config/env.config";
import { buildOpenApiSpec } from "./config/openapi/openapi.registry";
import { registerFileOpenApi } from "./modules/files/file.openapi";

// Khởi tạo các định nghĩa OpenAPI
registerFileOpenApi();

// SEC-45: Đảm bảo JSON.stringify tuần tự hóa an toàn kiểu dữ liệu BigInt sang số nguyên chuẩn
if (typeof (BigInt.prototype as any).toJSON !== "function") {
  (BigInt.prototype as any).toJSON = function () {
    return Number(this);
  };
}

/**
 * Express Application cho Media & File Storage Microservice (Phase 6: Second Satellite Service)
 *
 * Đảm nhiệm:
 * - REST API cho File & Media domain (/api/v1/files/*)
 * - Xử lý presigned upload/download URLs với Cloudflare R2 / S3
 * - Tối ưu hóa, resize, crop và chuyển đổi định dạng ảnh bằng Sharp (WebP, AVIF, JPEG, PNG)
 * - Quét dọn tệp tin rác mồ côi (orphan & unconfirmed files cleanup)
 * - Health check cho API Gateway (Traefik) load balancer
 */
const mediaApp = express();

mediaApp.set("trust proxy", envConfig.trustProxy);

// 1. Distributed Tracing & Security Headers
mediaApp.use(requestIdMiddleware);
mediaApp.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:", "blob:"],
      },
    },
    crossOriginResourcePolicy: { policy: "cross-origin" },
  }),
);

// 2. CORS Handling
const corsOptions: cors.CorsOptions = {
  origin: (origin, callback) => {
    const allowed = envConfig.cors.allowedOrigins.map((o) =>
      o.replace(/\/+$/, ""),
    );
    if (!origin) {
      callback(null, true);
      return;
    }
    const cleanOrigin = origin.replace(/\/+$/, "");
    if (allowed.includes("*")) {
      if (envConfig.nodeEnv !== "production") {
        callback(null, true);
        return;
      }
      console.error(
        "[CORS] CORS_ALLOWED_ORIGINS=* is not permitted in production.",
      );
      callback(null, false);
      return;
    }
    if (allowed.includes(cleanOrigin)) {
      callback(null, true);
    } else {
      callback(null, false);
    }
  },
  credentials: true,
};
mediaApp.use(cors(corsOptions));
mediaApp.use(morgan(envConfig.nodeEnv === "production" ? "combined" : "dev"));
mediaApp.use(express.json({ limit: "20mb" }));
mediaApp.use(express.urlencoded({ extended: true, limit: "20mb" }));
mediaApp.use(cookieParser());

// 3. Health check endpoints cho Traefik Gateway & Monitoring
const healthHandler = (_req: express.Request, res: express.Response) => {
  res.status(200).json({
    status: "ok",
    service: "media-service",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
};

mediaApp.get("/health", healthHandler);
mediaApp.get("/api/v1/files/health", healthHandler);
mediaApp.get("/files/health", healthHandler);

// 3.1 OpenAPI Specification Endpoint (Chỉ mở trên dev/staging, ẩn trên production)
if (envConfig.nodeEnv !== "production") {
  mediaApp.get("/openapi.json", (_req, res) => res.status(200).json(buildOpenApiSpec()));
  mediaApp.get("/api/v1/files/openapi.json", (_req, res) => res.status(200).json(buildOpenApiSpec()));
}

// 4. Mount File & Media Routes (dual-mount hỗ trợ cả prefix /api/v1/files và /files)
// SEC-09: Mount requireGatewayOrigin để bảo vệ endpoints khỏi bypass API Gateway
mediaApp.use(
  "/api/v1/files",
  requireGatewayOrigin,
  rateLimitMiddleware,
  maintenanceGuard(),
  fileRoute,
);
mediaApp.use(
  "/files",
  requireGatewayOrigin,
  rateLimitMiddleware,
  maintenanceGuard(),
  fileRoute,
);

// 5. Error handling middlewares
mediaApp.use(notFoundMiddleware);
mediaApp.use(errorMiddleware);

export default mediaApp;
