import { PrismaClient as MediaPrismaClient } from "@prisma/client-media";
import { envConfig } from "../config/env.config";

/**
 * Cấu hình timeout mặc định cho interactive transactions (Serializable / Heavy Load)
 * Tránh lỗi timeout 5s mặc định khi hệ thống chịu tải cao hoặc độ trễ mạng đám mây.
 */
export const DEFAULT_MEDIA_TRANSACTION_OPTIONS = {
  maxWait: 10000,
  timeout: 15000,
} as const;

export const DEFAULT_TRANSACTION_OPTIONS = DEFAULT_MEDIA_TRANSACTION_OPTIONS;

export type MediaPrismaClientType = MediaPrismaClient;

let _mediaPrisma: MediaPrismaClient | null = null;

export function getMediaPrisma(): MediaPrismaClient {
  if (!_mediaPrisma) {
    // SEC-34: Bind Prisma client constructor to dynamic database URL resolved by envConfig
    _mediaPrisma = new MediaPrismaClient({
      datasources: {
        db: {
          url: envConfig.database.url,
        },
      },
      log:
        envConfig.nodeEnv === "development"
          ? ["query", "error", "warn"]
          : ["error", "warn"],
    });
  }
  return _mediaPrisma;
}

export const mediaPrisma = new Proxy({} as MediaPrismaClient, {
  get(_target, prop) {
    return (getMediaPrisma() as any)[prop];
  },
  set(_target, prop, value) {
    (getMediaPrisma() as any)[prop] = value;
    return true;
  },
});

export const prisma = mediaPrisma;
